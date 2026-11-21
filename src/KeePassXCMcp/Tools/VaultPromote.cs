using System.ComponentModel;
using KeePassXCMcp.Infra;
using ModelContextProtocol.Server;

namespace KeePassXCMcp.Tools;

[McpServerToolType]
public static class VaultPromoteTool
{
    [McpServerTool(Name = "vault_promote")]
    [Description(
        "Record a promotion REQUEST for the human approver: snapshots the staging database " +
        "(entries + attachment sha256/size) into a pending-request file. This performs NO merge: " +
        "this server process does not have — and can never obtain — the main vault password. " +
        "A human must approve in a real terminal: they run `keepassxc-mcp promote` themselves, " +
        "or (only after they agree in chat) you call vault_open_approver to pop that window for " +
        "them. Returns what was recorded and where.")]
    public static async Task<string> RunAsync()
    {
        try
        {
            var snapshot = await StagingOps.SnapshotStagingAsync(VaultContext.Config, VaultContext.Cli, VaultContext.Staging);
            if (snapshot.Entries.Count == 0)
                return "Nothing staged — staging database is empty. No promotion request recorded.";

            var request = new PendingRequest
            {
                RequestedAtUtc = snapshot.SnapshotAtUtc,
                MainVaultPath = VaultContext.Config.MainVaultPath,
                Entries = snapshot.Entries.Select(e => new StagedEntryInfo(e.Path, e.Group, e.Title, e.Notes)).ToList(),
                Attachments = snapshot.Entries.SelectMany(e => e.Attachments).ToList(),
            };
            PendingRequest.Save(VaultContext.Paths, request);

            return
                $"Promotion request recorded at {VaultContext.Paths.PendingFile}\n" +
                $"{request.Entries.Count} entries, {request.Attachments.Count} attachments awaiting human approval.\n" +
                "NOTHING has been merged into the main vault and this process can never merge it. " +
                "The human approves in their own terminal: they run `keepassxc-mcp promote`, or " +
                "after you ask them and they agree, vault_open_approver pops that window for them.\n" +
                StagingOps.ToJson(request);
        }
        catch (Exception ex) when (ex is ArgumentException or KeePassCliException or InvalidOperationException)
        {
            return "Error: " + Redact.Apply(ex.Message, VaultContext.Config.KnownSecrets);
        }
    }
}
