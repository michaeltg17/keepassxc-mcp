using System.Diagnostics;
using KeePassXCMcp.Infra;

namespace KeePassXCMcp.Tests;

/// <summary>SPEC.md open question 1, tested: entry UUIDs survive staging → merge. The
/// provenance sidecar's corroborating UUID key relies on this.</summary>
public class MergeUuidStabilityTests
{
    [RequiresCliFact]
    public async Task Promote_PreservesEntryUuid()
    {
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "UuidCheck", "note body");
        var stagingShow = ShowParser.Parse(
            (await h.Cli.ShowAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/UuidCheck")).StdOut);
        Assert.NotEmpty(stagingShow.Uuid);

        await h.RecordPromotionRequestAsync();

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
        psi.Environment["KEEPASSXC_MCP_CONFIG"] = h.Paths.ConfigFile;
        using var proc = Process.Start(psi)!;
        proc.StandardInput.WriteLine("y");
        proc.StandardInput.WriteLine(VaultHarness.MainPassword);
        proc.StandardInput.Close();
        await proc.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);
        Assert.Equal((int)Promoter.Exit.Ok, proc.ExitCode);

        var mainShow = ShowParser.Parse(await h.ShowMainAsync("Inbox/UuidCheck"));
        Assert.Equal(stagingShow.Uuid, mainShow.Uuid);
    }
}
