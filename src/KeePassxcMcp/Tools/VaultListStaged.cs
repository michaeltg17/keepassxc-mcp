using System.ComponentModel;
using KeePassxcMcp.Infra;
using ModelContextProtocol.Server;

namespace KeePassxcMcp.Tools;

[McpServerToolType]
public static class VaultListStagedTool
{
    [McpServerTool(Name = "vault_list_staged")]
    [Description(
        "List everything currently staged in the sandbox database: entries with notes and " +
        "per-attachment name/size/sha256 (hashes computed from the staging database itself). " +
        "Read-only; touches only the staging database, never the main vault.")]
    public static async Task<string> RunAsync()
    {
        try
        {
            var snapshot = await StagingOps.SnapshotStagingAsync(VaultContext.Config, VaultContext.Cli, VaultContext.Staging);
            var attachmentCount = snapshot.Entries.Sum(e => e.Attachments.Count);
            return $"Staged entries: {snapshot.Entries.Count} ({attachmentCount} attachments). " +
                   "Call vault_promote to record a promotion request for the human approver.\n" +
                   StagingOps.ToJson(snapshot);
        }
        catch (Exception ex) when (ex is ArgumentException or KeePassCliException or InvalidOperationException)
        {
            return "Error: " + Redact.Apply(ex.Message, VaultContext.Config.KnownSecrets);
        }
    }
}
