using System.Diagnostics;

namespace KeePassxcMcp.Tests;

/// <summary>`status` mode: shows config + staging + pending, stagingPassword redacted.</summary>
public class StatusModeTests
{
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
        var stdout = await proc.StandardOutput.ReadToEndAsync();
        await proc.WaitForExitAsync();

        Assert.Equal(0, proc.ExitCode);
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
