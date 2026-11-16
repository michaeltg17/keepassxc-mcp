using System.ComponentModel;
using KeePassxcMcp.Infra;
using ModelContextProtocol.Server;

namespace KeePassxcMcp.Tools;

[McpServerToolType]
public static class VaultStageEntryTool
{
    [McpServerTool(Name = "vault_stage_entry")]
    [Description(
        "Stage one entry (title + notes + optional file attachments) into the sandbox STAGING database. " +
        "The real KeePassXC vault is NEVER touched — a human runs `keepassxc-mcp promote` in a terminal " +
        "to merge staged content after reviewing it. Re-staging the same group+title updates notes and " +
        "overwrites attachments of the same attachment file names. Returns a JSON receipt with sha256/size " +
        "per attachment, computed from the attachment AS STORED in the staging database.")]
    public static async Task<string> RunAsync(
        [Description("Entry title (required). Must not contain '/'.")] string title,
        [Description("Group path inside the staging database, e.g. 'Inbox' or 'Work/Reports' (created if missing). Omit for root.")] string? group = null,
        [Description("Notes body for the entry.")] string? notes = null,
        [Description("Absolute paths of files on disk to attach. Stored under their file names.")] string[]? files = null)
    {
        try
        {
            var receipt = await StagingOps.StageEntryAsync(
                VaultContext.Config, VaultContext.Cli, VaultContext.Staging, group, title, notes, files);
            return "Staged into sandbox (main vault untouched).\n" + StagingOps.ToJson(receipt);
        }
        catch (Exception ex) when (ex is ArgumentException or KeePassCliException or InvalidOperationException)
        {
            return "Error: " + Redact.Apply(ex.Message, VaultContext.Config.KnownSecrets);
        }
    }
}
