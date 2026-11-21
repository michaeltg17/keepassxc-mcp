using System.ComponentModel;
using KeePassXCMcp.Infra;
using ModelContextProtocol.Server;

namespace KeePassXCMcp.Tools;

[McpServerToolType]
public static class VaultOpenApproverTool
{
    [McpServerTool(Name = "vault_open_approver")]
    [Description(
        "Open the human approver in a NEW terminal window on the user's machine: launches this " +
        "same executable in promote mode as an independent process. It receives nothing from " +
        "this server — the human reviews the live merge diff, confirms y, and types the main " +
        "vault master password INTO THAT WINDOW, where this process can never see it. " +
        "ONLY call this after ALL of: (1) staging is complete, (2) vault_promote recorded a " +
        "pending request, and (3) the user explicitly agreed in chat that you may open the " +
        "approval prompt now. Refuses when there is no pending request, or when " +
        "allowAgentApproverWindow is false in config — then the human must run " +
        "`keepassxc-mcp promote` themselves instead.")]
    public static string Run()
    {
        var cfg = VaultContext.Config;
        if (!cfg.AllowApproverWindow)
            return
                "Refused: allowAgentApproverWindow is false in config — the approver may only be " +
                "launched by the human. Ask the user to run `keepassxc-mcp promote` in their own terminal.";

        var request = PendingRequest.TryLoad(VaultContext.Paths);
        if (request is null)
            return
                "Refused: no pending promotion request exists. Stage the entries and call " +
                "vault_promote first; only then may an approval prompt be opened.";

        var result = ApproverLauncher.TryOpenPromoteWindow();
        if (!result.Launched)
            return
                $"Could not open an approver window ({result.Detail}).\n" +
                "The recorded request is untouched — ask the user to run `keepassxc-mcp promote` " +
                "in a terminal themselves.";

        return
            $"Approver window opened via {result.Method}: {result.Detail}\n" +
            "For review in that window: " + string.Join(", ", request.Entries.Select(e => e.Path)) +
            $" ({request.Attachments.Count} attachments).\n" +
            "The human must press Enter, read the manifest and live dry-run diff, confirm y, and type " +
            "the master password IN THAT WINDOW. This server cannot see any of it and gets no result — " +
            "ask the user afterwards, or have them run `keepassxc-mcp status`. " +
            "If the window did not appear, have them run `keepassxc-mcp promote` manually.";
    }
}
