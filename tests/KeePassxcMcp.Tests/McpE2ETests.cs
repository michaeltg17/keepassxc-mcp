using System.Diagnostics;
using System.Runtime.InteropServices;
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
                await CloseApproverWindowsAsync();
        }
        Assert.True(
            enabledReply.Contains("Approver window opened via") || enabledReply.Contains("Could not open an approver window"),
            "expected a launched window or the honest manual fallback, got: " + enabledReply);
        Assert.NotNull(PendingRequest.TryLoad(harness.Paths)); // the launcher never consumes the request
    }

    /// <summary>Test hygiene only: the approver window opened above stays open on purpose
    /// (cmd /k keeps the outcome readable for a human) — that is correct product behavior,
    /// so it is closed HERE, never in product code. Located via the real chain:
    /// this test → MCP server child (cmd's parent) → cmd window → its promote child.</summary>
    private static async Task CloseApproverWindowsAsync()
    {
        if (!OperatingSystem.IsWindows()) return; // other launchers have no such child tree
        var serverName = Path.GetFileNameWithoutExtension(VaultHarness.ServerExePath);
        for (var attempt = 0; attempt < 10; attempt++) // the window takes a moment to appear
        {
            var parentOf = SnapshotParentPids();
            // OUR server processes only (not e.g. the user's live MCP connection): the
            // parent chain must lead back to this test process, however deeply nested.
            var ourServerPids = Process.GetProcessesByName(serverName)
                .Select(p => p.Id)
                .Where(id => TracesToThisTest(id, parentOf))
                .ToHashSet();
            foreach (var window in Process.GetProcessesByName("cmd").Select(p => p.Id)
                         .Where(id => ourServerPids.Contains(parentOf.GetValueOrDefault(id))))
            {
                try { Process.GetProcessById(window).Kill(entireProcessTree: true); return; }
                catch (ArgumentException) { } // already gone
                catch (InvalidOperationException) { } // already gone
            }
            await Task.Delay(500, TestContext.Current.CancellationToken);
        }
        // Not found: the verdict above already stands; hygiene must never change it.
    }

    private static bool TracesToThisTest(int pid, IReadOnlyDictionary<int, int> parentOf)
    {
        for (var hop = 0; hop < 8 && parentOf.TryGetValue(pid, out var parent); pid = parent)
            if (parent == Environment.ProcessId) return true;
        return false;
    }

    // pid -> parent pid, via the standard kernel32 process snapshot.
    private static Dictionary<int, int> SnapshotParentPids()
    {
        var map = new Dictionary<int, int>();
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap.ToInt64() is 0 or -1) return map;
        try
        {
            var entry = new ProcessEntry32 { DwSize = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snap, ref entry)) return map;
            do map[(int)entry.Th32ProcessId] = (int)entry.Th32ParentProcessId;
            while (Process32Next(snap, ref entry));
        }
        catch
        {
            // best-effort: an empty map just means "nothing to close this attempt"
        }
        finally { CloseHandle(snap); }
        return map;
    }

    private const uint TH32CS_SNAPPROCESS = 0x2;

    [DllImport("kernel32.dll")] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint DwSize;
        public uint CntUsage;
        public uint Th32ProcessId;
        public IntPtr Th32DefaultHeapId;
        public uint Th32ModuleId;
        public uint CntThreads;
        public uint Th32ParentProcessId;
        public int PcPriClassBase;
        public uint DwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExeFile;
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
