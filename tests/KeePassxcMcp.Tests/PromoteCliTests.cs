using System.Diagnostics;
using System.Text;
using KeePassxcMcp.Infra;

namespace KeePassxcMcp.Tests;

/// <summary>End-to-end CLI approver tests: drive `keepassxc-mcp promote` as a child
/// process feeding stdin ("y\n&lt;pw&gt;\n" / deny "n"), exactly the human flow.</summary>
public class PromoteCliTests
{
    private static async Task<(Promoter.Exit Exit, string StdOut, string StdErr)> RunPromoteAsync(
        VaultHarness harness, params string[] stdinLines)
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
        psi.Environment["KEEPASSXC_MCP_CONFIG"] = harness.Paths.ConfigFile;

        using var proc = Process.Start(psi)!;
        foreach (var line in stdinLines) proc.StandardInput.WriteLine(line);
        proc.StandardInput.Close();
        var stdout = await proc.StandardOutput.ReadToEndAsync();
        var stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        // the OS int meets the typed contract exactly here:
        return ((Promoter.Exit)proc.ExitCode, stdout, stderr);
    }

    [RequiresCliFact]
    public async Task Approve_MergesVerifiesFlushesAndClearsRequest()
    {
        using var h = await VaultHarness.CreateAsync();
        var source = h.CreateAttachmentFile("contract.pdf", 3072);
        await h.StageAsync("Inbox/Legal", "Contract", "signed copy", source);
        var request = await h.RecordPromotionRequestAsync();
        var expectedSha = Assert.Single(request.Attachments).Sha256;

        var (exit, stdout, stderr) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);

        Assert.Equal(Promoter.Exit.Ok, exit);
        // dry-run diff printed on stdout (the human's actual review surface):
        Assert.Matches("Added:|Creating missing", stdout);
        Assert.Contains("Contract", stderr + stdout);
        // merge happened, attachment present with matching hash:
        Assert.True(await h.MainHasEntryAsync("Inbox/Legal/Contract"));
        var show = ShowParser.Parse(await h.ShowMainAsync("Inbox/Legal/Contract"));
        var att = Assert.Single(show.Attachments);
        Assert.Equal("contract.pdf", att.Name);
        var (sha, _) = await KeePassxcMcp.Tools.StagingOps.HashStoredAttachmentAsync(
            h.Config, h.Cli, h.MainPath, VaultHarness.MainPassword, null, "Inbox/Legal/Contract", "contract.pdf");
        Assert.Equal(expectedSha, sha);
        // staging flushed, request cleared, state recorded:
        Assert.Empty(await h.StagedEntryPathsAsync());
        Assert.Null(PendingRequest.TryLoad(h.Paths));
        var state = PromoterState.Load(h.Paths);
        Assert.NotNull(state.LastPromotedUtc);
        Assert.NotNull(state.LastMainMtimeUtc);
    }

    [RequiresCliFact]
    public async Task Approve_WithKeyfileVault()
    {
        using var h = await VaultHarness.CreateAsync(mainWithKeyfile: true);
        var source = h.CreateAttachmentFile("keynote.txt", 128);
        await h.StageAsync("Inbox", "WithKeyfile", "main vault uses keyfile", source);
        await h.RecordPromotionRequestAsync();

        var (exit, stdout, _) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);

        Assert.Equal(Promoter.Exit.Ok, exit);
        Assert.Matches("Added:|Creating missing", stdout);
        Assert.True(await h.MainHasEntryAsync("Inbox/WithKeyfile"));
        Assert.Empty(await h.StagedEntryPathsAsync());
    }

    [RequiresCliFact]
    public async Task Deny_IsNoOp()
    {
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "DeniedEntry", "should never merge", h.CreateAttachmentFile("x.bin", 64));
        await h.RecordPromotionRequestAsync();

        var (exit, _, stderr) = await RunPromoteAsync(h, "n");

        Assert.Equal(Promoter.Exit.Denied, exit);
        Assert.Contains("Denied", stderr);
        Assert.False(await h.MainHasEntryAsync("Inbox/DeniedEntry"));
        Assert.Single(await h.StagedEntryPathsAsync());          // staging untouched
        Assert.NotNull(PendingRequest.TryLoad(h.Paths));          // request kept
    }

    [RequiresCliFact]
    public async Task NoPendingRequest_Refuses()
    {
        using var h = await VaultHarness.CreateAsync();
        var (exit, _, stderr) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);
        Assert.Equal(Promoter.Exit.Error, exit);
        Assert.Contains("No pending promotion request", stderr);
    }

    [RequiresCliFact]
    public async Task WrongPasswordThenEof_AbortsAsNoOp()
    {
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "Protected", "body", h.CreateAttachmentFile("y.bin", 64));
        await h.RecordPromotionRequestAsync();

        // attempt 1 wrong, attempt 2 hits closed stdin (EOF) -> clean no-op abort
        var (exit, _, stderr) = await RunPromoteAsync(h, "y", "totally-wrong-password");

        Assert.Equal(Promoter.Exit.Denied, exit);
        Assert.Contains("Attempt failed", stderr);
        Assert.Contains("Input closed at the password prompt", stderr);
        Assert.False(await h.MainHasEntryAsync("Inbox/Protected"));
        Assert.Single(await h.StagedEntryPathsAsync());
        Assert.NotNull(PendingRequest.TryLoad(h.Paths));
    }

    [RequiresCliFact]
    public async Task WrongThenEmptyThenCorrect_MergesOnThirdAttempt()
    {
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "Retryable", "body", h.CreateAttachmentFile("z.bin", 64));
        await h.RecordPromotionRequestAsync();

        var (exit, stdout, stderr) = await RunPromoteAsync(h, "y", "wrong-one", "", VaultHarness.MainPassword);

        Assert.Equal(Promoter.Exit.Ok, exit);
        Assert.Contains("attempt 1/3", stderr);
        Assert.Contains("Empty password", stderr);
        Assert.Matches("Added:|Creating missing", stdout);
        Assert.True(await h.MainHasEntryAsync("Inbox/Retryable"));
        Assert.Empty(await h.StagedEntryPathsAsync());
        Assert.Null(PendingRequest.TryLoad(h.Paths));
    }

    [RequiresCliFact]
    public async Task ThreeFailedAttempts_StopsCleanly_KeepsEverything()
    {
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "Guarded", "body", h.CreateAttachmentFile("w.bin", 64));
        await h.RecordPromotionRequestAsync();

        var (exit, _, stderr) = await RunPromoteAsync(h, "y", "wrong-1", "wrong-2", "wrong-3");

        Assert.Equal(Promoter.Exit.Error, exit);
        Assert.Contains("attempt 3/3", stderr);
        Assert.Contains("3 password attempts failed", stderr);
        Assert.False(await h.MainHasEntryAsync("Inbox/Guarded"));
        Assert.Single(await h.StagedEntryPathsAsync());           // staging kept
        Assert.NotNull(PendingRequest.TryLoad(h.Paths));          // request kept
    }

    [RequiresCliFact]
    public async Task MtimeWarning_AppearsWhenMainChangedOutsideFlow()
    {
        using var h = await VaultHarness.CreateAsync();
        // Simulate a previous promote that recorded an older mtime, then touch the main vault.
        new PromoterState { LastPromotedUtc = DateTimeOffset.UtcNow.AddDays(-1), LastMainMtimeUtc = File.GetLastWriteTimeUtc(h.MainPath).AddMinutes(-30) }.Save(h.Paths);
        File.SetLastWriteTimeUtc(h.MainPath, DateTime.UtcNow.AddMinutes(5));

        await h.StageAsync("Inbox", "MtimeEntry", "body");
        await h.RecordPromotionRequestAsync();

        var (_, _, stderr) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);
        Assert.Contains("WARNING: main vault file changed", stderr);
    }
}
