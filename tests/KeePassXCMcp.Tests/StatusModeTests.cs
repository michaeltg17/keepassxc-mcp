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

        // when: the executable is asked for its version, then: exit 0 and a semver banner
        using var proc = Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);

        proc.ExitCode.Should().Be(0);
        stdout.Trim().Should().MatchRegex(@"^keepassxc-mcp \d+\.\d+\.\d+");
    }
    [RequiresCliFact]
    public async Task Status_PrintsRedactedConfigAndStagingState()
    {
        // given: one staged entry, one recorded promotion request, and a real config
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

        // when: `status` runs, then: it shows the human state — version, staged content,
        // pending request — with the staging password REDACTED, never printed…
        using var proc = Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);

        proc.ExitCode.Should().Be(0);
        stdout.Should().Contain("app version   : " + AppInfo.Version)
            .And.Contain("staged entries: 1").And.Contain("StatusEntry")
            .And.Contain("pending request : 1 entries").And.Contain("[REDACTED");
        // …and the one password that must never exist anywhere in this flow: the main
        // vault password is not part of config at all, so status cannot even see it.
        stdout.Should().NotContain(VaultHarness.StagingPassword);
        File.ReadAllText(harness.Paths.ConfigFile).Should().NotContain("mainVaultPassword");
    }
}
