using System.Security.Cryptography;
using KeePassXCMcp.Infra;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace KeePassXCMcp.Tests;

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

        // tools/list exposes the agent-side tools (the exact full surface is asserted in
        // McpSecretToolsTests.ToolList_IncludesNewFlowTools — here: these four must be live).
        var tools = await client.ListToolsAsync();
        tools.Select(t => t.Name).Should()
            .Contain("vault_stage_entry", "vault_list_staged", "vault_promote", "vault_open_approver");

        // tools/call vault_stage_entry → receipt with sha256/size.
        var stage = await client.CallToolAsync("vault_stage_entry", new Dictionary<string, object?>
        {
            ["group"] = "Inbox/Mcp",
            ["title"] = "McpEntry",
            ["notes"] = "staged over stdio",
            ["files"] = new[] { attachment },
        });
        var stageText = Text(stage);
        var expectedSha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(attachment)));
        stageText.Should().Contain("Staged into sandbox").And.Contain(expectedSha).And.Contain("900");

        // vault_list_staged shows it.
        var list = await client.CallToolAsync("vault_list_staged", new Dictionary<string, object?>());
        Text(list).Should().Contain("Inbox/Mcp/McpEntry").And.Contain("note.md");

        // vault_promote writes the PendingRequest with correct hashes — and merges nothing.
        var promote = await client.CallToolAsync("vault_promote", new Dictionary<string, object?>());
        Text(promote).Should().Contain("Promotion request recorded").And.Contain("can never merge");

        var pending = PendingRequest.TryLoad(harness.Paths);
        pending.Should().NotBeNull();
        var entry = Assert.Single(pending!.Entries);
        entry.Path.Should().Be("Inbox/Mcp/McpEntry");
        var att = Assert.Single(pending.Attachments);
        att.Name.Should().Be("note.md");
        att.SizeBytes.Should().Be(900);
        att.Sha256.Should().Be(expectedSha);

        // The main vault is untouched — the promote approval is a separate terminal process.
        (await harness.MainHasEntryAsync("Inbox/Mcp/McpEntry")).Should().BeFalse();
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
        Text(result).Should().Contain("Error");
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
            reply.Should().Contain("no pending promotion request");
        }

        await harness.StageAsync("Inbox", "Windowed", "body");
        await harness.RecordPromotionRequestAsync();

        // (b) request exists, but allowAgentApproverWindow=false in config → refusal
        harness.WriteConfigFile(harness.Config with { AllowAgentApproverWindow = false });
        {
            await using var client = await ConnectAsync(harness);
            var reply = Text(await client.CallToolAsync("vault_open_approver", new Dictionary<string, object?>()));
            reply.Should().Contain("allowAgentApproverWindow is false");
            PendingRequest.TryLoad(harness.Paths).Should().NotBeNull(); // refusal never consumes the request
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
        enabledReply.Should().MatchRegex("Approver window opened via|Could not open an approver window",
            "expected a launched window or the honest manual fallback");
        PendingRequest.TryLoad(harness.Paths).Should().NotBeNull(); // the launcher never consumes the request
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
