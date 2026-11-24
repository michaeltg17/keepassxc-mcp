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

        proc.ExitCode.Should().Be(0);
        stdout.Trim().Should().MatchRegex(@"^keepassxc-mcp \d+\.\d+\.\d+");
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

        proc.ExitCode.Should().Be(0);
        stdout.Should().Contain("app version   : " + AppInfo.Version)
            .And.Contain("staged entries: 1").And.Contain("StatusEntry")
            .And.Contain("pending request : 1 entries").And.Contain("[REDACTED");
        // stagingPassword value must NEVER appear in status output:
        stdout.Should().NotContain(VaultHarness.StagingPassword);
        // and the main vault password is never part of config at all:
        File.ReadAllText(harness.Paths.ConfigFile).Should().NotContain("mainVaultPassword");
    }
}
