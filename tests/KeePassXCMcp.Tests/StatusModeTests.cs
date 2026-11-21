using System.Diagnostics;
using KeePassXCMcp.Infra;

namespace KeePassXCMcp.Tests;

/// <summary>`status` mode: shows config + staging + pending, stagingPassword redacted.</summary>
public class StatusModeTests
{
    [Fact]
    public async Task Version_PrintsSemver()
    {
        var psi = new ProcessStartInfo
        {
            FileName = VaultHarness.ServerExePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("--version");

        using var proc = Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, proc.ExitCode);
        Assert.Matches(@"^keepassxc-mcp \d+\.\d+\.\d+", stdout.Trim());
    }
    [RequiresCliFact]
    public async Task Status_PrintsRedactedConfigAndStagingState()
    {
        using var harness = await VaultHarness.CreateAsync();
        await harness.StageAsync("Inbox", "StatusEntry", "body");
        await harness.RecordPromotionRequestAsync();

        var psi = new ProcessStartInfo
        {
            FileName = VaultHarness.ServerExePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("status");
        psi.Environment["KEEPASSXC_MCP_CONFIG"] = harness.Paths.ConfigFile;

        using var proc = Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, proc.ExitCode);
        Assert.Contains("app version   : " + AppInfo.Version, stdout);
        Assert.Contains($"staged entries: 1", stdout);
        Assert.Contains("StatusEntry", stdout);
        Assert.Contains("pending request : 1 entries", stdout);
        Assert.Contains("[REDACTED", stdout);
        // stagingPassword value must NEVER appear in status output:
        Assert.DoesNotContain(VaultHarness.StagingPassword, stdout);
        // and the main vault password is never part of config at all:
        Assert.DoesNotContain("mainVaultPassword", File.ReadAllText(harness.Paths.ConfigFile));
    }
}
