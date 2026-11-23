using System.ComponentModel;
using KeePassXCMcp.Infra;
using ModelContextProtocol.Server;

namespace KeePassXCMcp.Tools;

[McpServerToolType]
public static class VaultAuditTool
{
    [McpServerTool(Name = "vault_audit")]
    [Description(
        "Exposure audit (SPEC.md E3) — END-OF-TASK DUTY: if you used any vault tool in this " +
        "task, call this before finishing and surface the result to the user. Lists every " +
        "tracked secret with its provenance; entries tagged 'seen-by-model' were visible in " +
        "an agent conversation and SHOULD BE ROTATED (vault_rotate) or explicitly dismissed. " +
        "Reads only a local metadata file (paths + origins + fingerprints — no secret values).")]
    public static string Audit()
    {
        var store = ProvenanceStore.Load(VaultContext.Paths);
        if (store.Records.Count == 0)
            return "No tracked secrets. (Tracking covers only values written through this tool's flows — " +
                   "the rest of the vault is untouched and untracked.)";

        var exposed = store.Exposed;
        var lines = new List<string>
        {
            $"Tracked secrets: {store.Records.Count} (exposed to a model: {exposed.Count}).",
        };
        foreach (var r in store.Records)
        {
            var mark = r.Origin == Origin.SeenByModel ? "  <-- ROTATE or dismiss" : "";
            lines.Add($"- {r.Path}: {r.Origin} (changed {r.LastChangedUtc:O}){mark}");
        }
        if (exposed.Count > 0)
        {
            lines.Add("");
            lines.Add("RECOMMENDATION: rotate the seen-by-model entries — at the service side once promoted, or here with " +
                      "vault_rotate before promoting. The user may instead dismiss individual entries or delete the " +
                      "tracking file; security first: rotation is the default, dismissal needs their explicit choice.");
        }
        return string.Join("\n", lines);
    }

    [McpServerTool(Name = "vault_audit_dismiss")]
    [Description(
        "Dismiss exposure records ONLY after the user explicitly chose to (or confirmed the " +
        "secret was rotated at the service). With an entryPath, removes that one record; " +
        "without, discards the whole tracking file — always safe, it holds no secret values, " +
        "the worst case is an empty audit list.")]
    public static string Dismiss(
        [Description("Entry path to dismiss. Omit to discard the entire tracking file.")] string? entryPath = null)
    {
        if (string.IsNullOrWhiteSpace(entryPath))
        {
            var existed = File.Exists(VaultContext.Paths.ProvenanceFile);
            ProvenanceStore.Clear(VaultContext.Paths);
            return existed
                ? "Tracking file discarded (it never contained secret values). Future exposure tracking starts fresh."
                : "No tracking file existed — nothing to discard.";
        }
        var store = ProvenanceStore.Load(VaultContext.Paths);
        if (!store.Remove(entryPath.Trim()))
            return $"No record for '{entryPath}'. Nothing removed.";
        store.Save(VaultContext.Paths);
        return $"Dismissed exposure record for '{entryPath}'. Remaining tracked: {store.Records.Count}.";
    }
}
