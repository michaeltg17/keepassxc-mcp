using System.ComponentModel;
using KeePassXCMcp.Infra;
using ModelContextProtocol.Server;

namespace KeePassXCMcp.Tools;

[McpServerToolType]
public static class VaultStagedRemoveTool
{
    [McpServerTool(Name = "vault_staged_remove")]
    [Description(
        "Discard a STAGED entry from the sandbox before it is promoted — the delete half of " +
        "staging. Operates ONLY on the staging database; the main vault is never touched. " +
        "RECYCLE, NOT PURGE: keepassxc-cli `rm` parks the entry in the staging database's " +
        "Recycle Bin (no CLI purge exists); recovery is the KeePassXC GUI. Safe by design — " +
        "staging is not a confidentiality boundary. The entry disappears from " +
        "vault_list_staged and the promotion manifest; provenance drops it too. If a later " +
        "vault_search surfaces the entry under 'Recycle Bin/…', that is the parked copy. " +
        "confirm must equal entryPath exactly — the deliberate friction step.")]
    public static async Task<string> RunAsync(
        [Description("Staged entry path, exactly as listed by vault_list_staged, e.g. 'Inbox/Mcp/McpEntry'.")] string entryPath,
        [Description("Must be the exact same string as entryPath — repetition is the confirmation.")] string confirm)
    {
        try
        {
            var receipt = await StagingOps.RemoveStagedAsync(
                VaultContext.Config, VaultContext.Paths, VaultContext.Cli, VaultContext.Staging,
                entryPath, confirm);
            return "Removed from staging — RECYCLED, not purged. Recover via the KeePassXC GUI " +
                   "(open the staging database → Recycle Bin → restore). Main vault untouched.\n" +
                   StagingOps.ToJson(receipt);
        }
        catch (Exception ex) when (ex is ArgumentException or KeePassCliException or InvalidOperationException)
        {
            return "Error: " + Redact.Apply(ex.Message, VaultContext.Config.KnownSecrets);
        }
    }
}
