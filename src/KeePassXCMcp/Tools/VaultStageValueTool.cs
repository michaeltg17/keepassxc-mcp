using System.ComponentModel;
using KeePassXCMcp.Infra;
using ModelContextProtocol.Server;

namespace KeePassXCMcp.Tools;

[McpServerToolType]
public static class VaultStageValueTool
{
    [McpServerTool(Name = "vault_stage_value")]
    [Description(
        "Stage an EXISTING secret value you already hold (F2.2/F3) — e.g. a service printed " +
        "its one-time key into a tool output. HONESTY REQUIREMENT: the value you pass here is " +
        "recorded as provenance 'seen-by-model' and will be listed by vault_audit as exposed — " +
        "prefer piping it straight in (`echo … | keepassxc-mcp stage --label …` keeps the value " +
        "out of the conversation entirely). The value travels to the staging database and is " +
        "never echoed back in the receipt. Staged only; promote to move it into the vault.")]
    public static async Task<string> RunAsync(
        [Description("Entry label path, e.g. 'Services/github-deploy-key'. Groups are created if missing.")] string label,
        [Description("The secret value (single line). It will be tagged seen-by-model.")] string value,
        [Description("Optional notes body for the entry.")] string? notes = null,
        [Description("Optional username field for the entry.")] string? username = null,
        [Description("Optional URL field for the entry.")] string? url = null)
    {
        try
        {
            var receipt = await SecretOps.StageValueAsync(
                VaultContext.Config, VaultContext.Paths, VaultContext.Cli, VaultContext.Staging,
                label, new Secret(value), Origin.SeenByModel, notes, username, url);
            return "Staged into sandbox (main vault untouched). TAGGED seen-by-model: the value was visible " +
                   "in this conversation, so it is on the vault_audit rotation list — recommend rotating it at the " +
                   "service once promoted.\n" + StagingOps.ToJson(receipt);
        }
        catch (Exception ex) when (ex is ArgumentException or KeePassCliException or InvalidOperationException)
        {
            return "Error: " + Redact.Apply(ex.Message, VaultContext.Config.KnownSecrets);
        }
    }
}
