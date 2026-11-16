using System.Diagnostics;
using System.Text.Json;
using KeePassxcMcp.Infra;
using KeePassxcMcp.Tools;

namespace KeePassxcMcp.Tests;

/// <summary>The agent-openable approver window (vault_open_approver / promote-window):
/// refusals, config opt-out, identity banner. Window-spawn itself is environment-dependent
/// (headless CI falls back to manual), so the launch test accepts both honest outcomes.</summary>
public class ApproverWindowTests
{
    private static (string Dir, VaultConfig Cfg, ConfigPaths Paths) TempConfig(bool? allowWindow = null)
    {
        var dir = Path.Combine(Path.GetTempPath(), "kpxc-mcp-apw-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var paths = new ConfigPaths(dir, Path.Combine(dir, "config.json"));
        var cfg = new VaultConfig(
            MainVaultPath: Path.Combine(dir, "main.kdbx"),
            MainKeyfilePath: null,
            StagingVaultPath: Path.Combine(dir, "staging.kdbx"),
            StagingPassword: "unused",
            KeepassxcCliPath: CliProbe.PathOrNull ?? "keepassxc-cli", // never invoked in these cases
            AllowAgentApproverWindow: allowWindow);
        File.WriteAllText(paths.ConfigFile, JsonSerializer.Serialize(cfg,
            new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        return (dir, cfg, paths);
    }

    [Fact]
    public void OpenApprover_RefusesWithoutPendingRequest()
    {
        var (dir, cfg, paths) = TempConfig();
        try
        {
            VaultContext.Init(cfg, paths);
            var reply = VaultOpenApproverTool.Run();
            Assert.Contains("no pending promotion request", reply);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [RequiresCliFact]
    public async Task OpenApprover_RefusesWhenDisabledByConfig()
    {
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "Gated", "body");
        await h.RecordPromotionRequestAsync();

        VaultContext.Init(h.Config with { AllowAgentApproverWindow = false }, h.Paths);
        var reply = VaultOpenApproverTool.Run();

        Assert.Contains("allowAgentApproverWindow is false", reply);
        Assert.NotNull(PendingRequest.TryLoad(h.Paths)); // request untouched
    }

    [RequiresCliFact]
    public async Task OpenApprover_OpensWindowOrHonestManualFallback()
    {
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "Windowed", "body");
        await h.RecordPromotionRequestAsync();

        VaultContext.Init(h.Config, h.Paths);
        var reply = VaultOpenApproverTool.Run();

        Assert.True(
            reply.Contains("Approver window opened via") || reply.Contains("Could not open an approver window"),
            "expected either a launched window or the honest manual fallback: " + reply);
        Assert.NotNull(PendingRequest.TryLoad(h.Paths)); // launching never consumes the request
    }

    [Fact]
    public async Task Promote_BannerIdentifiesItsOwnExecutable()
    {
        var (dir, _, paths) = TempConfig();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = VaultHarness.ServerExePath,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("promote");
            psi.Environment["KEEPASSXC_MCP_CONFIG"] = paths.ConfigFile;

            using var proc = Process.Start(psi)!;
            proc.StandardInput.Close();
            var stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            // no pending request → refuses, but the identity banner always prints first
            Assert.Equal(1, proc.ExitCode);
            Assert.Contains(VaultHarness.ServerExePath, stderr);
            Assert.Matches(@"its sha256\s*: [0-9a-f]{64}", stderr);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}
