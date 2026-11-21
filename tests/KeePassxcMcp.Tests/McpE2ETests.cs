using System.Security.Cryptography;
using KeePassxcMcp.Infra;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace KeePassxcMcp.Tests;

/// <summary>End-to-end MCP protocol test: launches the built exe in mcp mode, speaks
/// stdio JSON-RPC through the official SDK client — initialize, tools/list, tools/call.</summary>
public class McpE2ETests
{
    private static string Text(CallToolResult result) =>
        string.Join("\n", result.Content.OfType<TextContentBlock>().Select(c => c.Text));

    [RequiresCliFact]
    public async Task Initialize_ListTools_Stage_List_Promote()
    {
        using var harness = await VaultHarness.CreateAsync();
        var attachment = harness.CreateAttachmentFile("note.md", 900);

        var transport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "keepassxc-mcp",
            Command = VaultHarness.ServerExePath,
            Arguments = ["mcp"],
            EnvironmentVariables = new Dictionary<string, string?> { ["KEEPASSXC_MCP_CONFIG"] = harness.Paths.ConfigFile },
        });
        await using var client = await McpClient.CreateAsync(transport);

        // tools/list exposes exactly the four agent-side tools.
        var tools = await client.ListToolsAsync();
        Assert.Contains("vault_stage_entry", tools.Select(t => t.Name));
        Assert.Contains("vault_list_staged", tools.Select(t => t.Name));
        Assert.Contains("vault_promote", tools.Select(t => t.Name));
        Assert.Contains("vault_open_approver", tools.Select(t => t.Name));

        // tools/call vault_stage_entry → receipt with sha256/size.
        var stage = await client.CallToolAsync("vault_stage_entry", new Dictionary<string, object?>
        {
            ["group"] = "Inbox/Mcp",
            ["title"] = "McpEntry",
            ["notes"] = "staged over stdio",
            ["files"] = new[] { attachment },
        });
        var stageText = Text(stage);
        Assert.Contains("Staged into sandbox", stageText);
        var expectedSha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(attachment)));
        Assert.Contains(expectedSha, stageText);
        Assert.Contains("900", stageText);

        // vault_list_staged shows it.
        var list = await client.CallToolAsync("vault_list_staged", new Dictionary<string, object?>());
        Assert.Contains("Inbox/Mcp/McpEntry", Text(list));
        Assert.Contains("note.md", Text(list));

        // vault_promote writes the PendingRequest with correct hashes — and merges nothing.
        var promote = await client.CallToolAsync("vault_promote", new Dictionary<string, object?>());
        Assert.Contains("Promotion request recorded", Text(promote));
        Assert.Contains("can never merge", Text(promote));

        var pending = PendingRequest.TryLoad(harness.Paths);
        Assert.NotNull(pending);
        var entry = Assert.Single(pending.Entries);
        Assert.Equal("Inbox/Mcp/McpEntry", entry.Path);
        var att = Assert.Single(pending.Attachments);
        Assert.Equal("note.md", att.Name);
        Assert.Equal(900, att.SizeBytes);
        Assert.Equal(expectedSha, att.Sha256);

        // The main vault is untouched — the promote approval is a separate terminal process.
        Assert.False(await harness.MainHasEntryAsync("Inbox/Mcp/McpEntry"));
    }

    [RequiresCliFact]
    public async Task StageEntry_BadTitle_ReturnsError_NotCrash()
    {
        using var harness = await VaultHarness.CreateAsync();
        await using var client = await ConnectAsync(harness);

        var result = await client.CallToolAsync("vault_stage_entry", new Dictionary<string, object?>
        {
            ["title"] = "Evil/Path",
        });
        Assert.Contains("Error", Text(result));
    }

    /// <summary>vault_open_approver over stdio: refuses without a request, refuses when
    /// config disables it, and otherwise launches a window or says so honestly (headless
    /// runners take the fallback path).</summary>
    [RequiresCliFact]
    public async Task OpenApprover_Stdio_RefusalsAndLaunchAttempt()
    {
        using var harness = await VaultHarness.CreateAsync();

        // (a) no pending request → refusal over the real protocol
        {
            await using var client = await ConnectAsync(harness);
            var reply = Text(await client.CallToolAsync("vault_open_approver", new Dictionary<string, object?>()));
            Assert.Contains("no pending promotion request", reply);
        }

        await harness.StageAsync("Inbox", "Windowed", "body");
        await harness.RecordPromotionRequestAsync();

        // (b) request exists, but allowAgentApproverWindow=false in config → refusal
        harness.WriteConfigFile(harness.Config with { AllowAgentApproverWindow = false });
        {
            await using var client = await ConnectAsync(harness);
            var reply = Text(await client.CallToolAsync("vault_open_approver", new Dictionary<string, object?>()));
            Assert.Contains("allowAgentApproverWindow is false", reply);
            Assert.NotNull(PendingRequest.TryLoad(harness.Paths)); // refusal never consumes the request
        }

        // (c) enabled: real window or honest manual fallback — never a silent nothing.
        harness.WriteConfigFile();
        string enabledReply;
        {
            await using var client = await ConnectAsync(harness);
            enabledReply = Text(await client.CallToolAsync("vault_open_approver", new Dictionary<string, object?>()));
            if (enabledReply.Contains("opened via"))
                await ApproverWindowCloser.CloseOpenedWindowAsync(VaultHarness.ServerExePath, TestContext.Current.CancellationToken);
        }
        Assert.True(
            enabledReply.Contains("Approver window opened via") || enabledReply.Contains("Could not open an approver window"),
            "expected a launched window or the honest manual fallback, got: " + enabledReply);
        Assert.NotNull(PendingRequest.TryLoad(harness.Paths)); // the launcher never consumes the request
    }

    private static async Task<McpClient> ConnectAsync(VaultHarness harness)
    {
        var transport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "keepassxc-mcp",
            Command = VaultHarness.ServerExePath,
            Arguments = ["mcp"],
            EnvironmentVariables = new Dictionary<string, string?> { ["KEEPASSXC_MCP_CONFIG"] = harness.Paths.ConfigFile },
        });
        return await McpClient.CreateAsync(transport);
    }
}
