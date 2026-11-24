using System.ComponentModel;
using KeePassXCMcp.Infra;
using ModelContextProtocol.Server;

namespace KeePassXCMcp.Tools;

[McpServerToolType]
public static class VaultReaderTools
{
    [McpServerTool(Name = "vault_reader_open")]
    [Description(
        "Open a MAIN-VAULT READ session: launches this executable in reader mode in a NEW " +
        "terminal window where the human types the master password ONCE (input hidden; the " +
        "server can never see it). The reader process services main-vault reads (vault_search, " +
        "vault_get) until it is closed, hits its idle timeout, or this server exits (orphan " +
        "guard). READS ONLY — it never writes the main vault; writes still go through " +
        "staging + vault_promote. Ask the user in chat before opening a password prompt.")]
    public static string Open()
    {
        if (ReaderProtocol.TryGetLiveSession(VaultContext.Paths, out var existing))
            return $"A reader session is already open (pid {existing.Pid}, since {existing.OpenedAtUtc:O}). " +
                   "Use vault_search / vault_get, or vault_reader_close to end it.";

        var result = ApproverLauncher.TryOpenReaderWindow(Environment.ProcessId);
        if (!result.Launched)
            return $"Could not open a reader window ({result.Detail}). The human can always run " +
                   "`keepassxc-mcp reader` in their own terminal instead.";

        return
            $"Reader window opened via {result.Method}: {result.Detail}\n" +
            "The human must press Enter, verify the identity banner, and type the master password " +
            "IN THAT WINDOW (max 3 attempts). This server cannot see the password or the prompt. " +
            "Then vault_search / vault_get work against the MAIN vault until the session closes " +
            "(idle timeout or vault_reader_close). If the window did not appear, have the human " +
            "run `keepassxc-mcp reader` manually.";
    }

    [McpServerTool(Name = "vault_reader_close")]
    [Description(
        "Close the main-vault read session: the reader process zeroes its in-memory password " +
        "and exits. Call this when read work is done instead of waiting for the idle timeout.")]
    public static async Task<string> Close()
    {
        if (!ReaderProtocol.TryGetLiveSession(VaultContext.Paths, out _))
            return "No reader session is open.";
        var result = await ReaderClient.SendAsync(VaultContext.Paths, "close", "", TimeSpan.FromSeconds(10));
        return result.Ok
            ? "Reader session closed; the password is gone from memory."
            : "Close request failed: " + Redact.Apply(result.Error ?? "unknown error", VaultContext.Config.KnownSecrets);
    }

    [McpServerTool(Name = "vault_search")]
    [Description(
        "Search the MAIN vault by term (needs an open reader session). Returns entry PATHS " +
        "only — labels, never values. Use vault_get on a path for metadata. Secret values " +
        "are never returned (SPEC.md F4); nothing you can see here is exposed to the model.")]
    public static async Task<string> SearchAsync(
        [Description("Search term matched against entry fields by keepassxc-cli.")] string term)
    {
        if (string.IsNullOrWhiteSpace(term))
            return "Error: term must not be empty.";
        var result = await ReaderClient.SendAsync(VaultContext.Paths, "search", term.Trim());
        if (!result.Ok)
            return "Error: " + Redact.Apply(result.Error ?? "search failed", VaultContext.Config.KnownSecrets);
        var lines = result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length == 0)
            return "No entries match. (Paths only — search never returns values.)";
        return $"{lines.Length} matching entries (paths only):\n" + string.Join("\n", lines.Select(p => "- " + p));
    }

    [McpServerTool(Name = "vault_get")]
    [Description(
        "Read one MAIN-vault entry by exact path (needs an open reader session). Returns " +
        "title, username, URL, UUID, notes, attachment names, and the recorded provenance " +
        "tag — the entry's PASSWORD VALUE IS NEVER INCLUDED and cannot be requested. " +
        "Use it to decide whether an entry exists or to see its non-secret fields.")]
    public static async Task<string> GetAsync(
        [Description("Exact entry path in the main vault, e.g. 'Services/webhook-secret'.")] string entryPath)
    {
        if (string.IsNullOrWhiteSpace(entryPath) || entryPath.Any(char.IsControl))
            return "Error: entryPath must be a non-empty single line.";
        var result = await ReaderClient.SendAsync(VaultContext.Paths, "get", entryPath.Trim());
        if (!result.Ok)
            return "Error: " + Redact.Apply(result.Error ?? "get failed", VaultContext.Config.KnownSecrets);

        var show = ShowParser.Parse(result.Output);
        if (string.IsNullOrEmpty(show.Title))
            return $"No entry found at '{entryPath}' (or it has no title). Search with vault_search to find paths.";

        var store = ProvenanceStore.Load(VaultContext.Paths);
        var prov = store.Records.FirstOrDefault(r => r.Path == entryPath.Trim() || (r.Uuid == show.Uuid && show.Uuid.Length > 0));

        var lines = new List<string>
        {
            $"Entry: {entryPath.Trim()}",
            $"Title: {show.Title}",
            $"UserName: {show.UserName}",
            $"URL: {show.Url}",
            $"UUID: {show.Uuid}",
            $"Provenance: {(prov is null ? "not tracked (only values written by this tool's flows are tracked)" : $"{prov.Origin}, fingerprint {prov.FingerprintSha256?[..Math.Min(12, prov.FingerprintSha256.Length)]}…")}",
            $"Notes:\n{show.Notes}",
        };
        if (show.Attachments.Count > 0)
            lines.Add("Attachments: " + string.Join(", ", show.Attachments.Select(a => $"{a.Name} ({a.SizeBytes} B)")));
        lines.Add("The password value is intentionally absent — this tool cannot expose it.");
        return string.Join("\n", lines);
    }
}
