using System.Diagnostics;
using System.Text;
using KeePassXCMcp.Infra;
using KeePassXCMcp.Tools;

namespace KeePassXCMcp.Tests;

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
        // given: a staged entry with a 3 KiB attachment and a recorded promotion request
        using var h = await VaultHarness.CreateAsync();
        var source = h.CreateAttachmentFile("contract.pdf", 3072);
        await h.StageAsync("Inbox/Legal", "Contract", "signed copy", source);
        var request = await h.RecordPromotionRequestAsync();
        var expectedSha = Assert.Single(request.Attachments).Sha256;

        // when: the human approves ("y") and types the main password once at the prompt
        var (exit, stdout, stderr) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);

        // then: success — the dry-run diff was printed for review (the human's actual
        // review surface), the entry and attachment are in MAIN with a matching hash…
        exit.Should().Be(Promoter.Exit.Ok);
        // dry-run diff printed on stdout (the human's actual review surface):
        stdout.Should().MatchRegex("Added:|Creating missing");
        (stderr + stdout).Should().Contain("Contract");
        // merge happened, attachment present with matching hash:
        (await h.MainHasEntryAsync("Inbox/Legal/Contract")).Should().BeTrue();
        var show = ShowParser.Parse(await h.ShowMainAsync("Inbox/Legal/Contract"));
        var att = Assert.Single(show.Attachments);
        att.Name.Should().Be("contract.pdf");
        var (sha, _) = await StagingOps.HashStoredAttachmentAsync(
            h.Config, h.Cli, h.MainPath, VaultHarness.MainPassword, null, "Inbox/Legal/Contract", "contract.pdf");
        sha.Should().Be(expectedSha);

        // …and the flow is finished honestly: staging flushed, request consumed, state
        // recorded for the next promote's staleness check.
        (await h.StagedEntryPathsAsync()).Should().BeEmpty();
        PendingRequest.TryLoad(h.Paths).Should().BeNull();
        var state = PromoterState.Load(h.Paths);
        state.LastPromotedUtc.Should().NotBeNull();
        state.LastMainMtimeUtc.Should().NotBeNull();
    }

    [RequiresCliFact]
    public async Task RecycledStagedEntries_AreNeitherListedNorPromoted()
    {
        // A human tidying staging uses `keepassxc-cli rm`, which parks entries in the
        // Recycle Bin. Parked entries are not staged content: they must not appear in
        // listings or promotion requests, and must never reach the main vault
        // (0.3.0 beta drill: they were listed, requested, and failed merge verification).
        // given: two staged entries, then one is removed straight from staging with
        // keepassxc-cli rm (a human tidying up) — which parks it in the Recycle Bin.
        // Parked entries are not staged content: they must not appear in listings or
        // promotion requests, and must never reach the main vault
        // (0.3.0 beta drill: they were listed, requested, and failed merge verification).
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "Keeper", "survives");
        await h.StageAsync("Inbox", "Undone", "deleted before promote");
        (await h.StagedEntryPathsAsync()).Should().HaveCount(2);

        var rm = await h.Cli.RemoveEntryAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Undone");
        Assert.True(rm.Success, rm.FailureSummary);

        // then: listings show exactly the survivor — no Recycle Bin entries, no sentinels;
        // the request promises only it; and the merge delivers only it
        var listed = await h.StagedEntryPathsAsync();
        listed.Should().Equal("Inbox/Keeper"); // exact ordered listing

        var request = await h.RecordPromotionRequestAsync();
        Assert.Single(request.Entries).Path.Should().Be("Inbox/Keeper");

        var (exit, _, stderr) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);
        exit.Should().Be(Promoter.Exit.Ok);
        (await h.MainHasEntryAsync("Inbox/Keeper")).Should().BeTrue();
        (await h.MainHasEntryAsync("Inbox/Undone")).Should().BeFalse(); // parked entry never merges
    }

    [RequiresCliFact]
    public async Task Approve_WithKeyfileVault()
    {
        // given: a main vault whose protection needs password AND keyfile
        using var h = await VaultHarness.CreateAsync(mainWithKeyfile: true);
        var source = h.CreateAttachmentFile("keynote.txt", 128);
        await h.StageAsync("Inbox", "WithKeyfile", "main vault uses keyfile", source);
        await h.RecordPromotionRequestAsync();

        // when: the human approves with the password (the keyfile comes from config)
        var (exit, stdout, _) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);

        // then: the merge works with the combined credentials, and the flow completes
        exit.Should().Be(Promoter.Exit.Ok);
        stdout.Should().MatchRegex("Added:|Creating missing");
        (await h.MainHasEntryAsync("Inbox/WithKeyfile")).Should().BeTrue();
        (await h.StagedEntryPathsAsync()).Should().BeEmpty();
    }

    [RequiresCliFact]
    public async Task Deny_IsNoOp()
    {
        // given: a staged entry (with attachment) and a recorded request
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "DeniedEntry", "should never merge", h.CreateAttachmentFile("x.bin", 64));
        await h.RecordPromotionRequestAsync();

        // when: the human says no
        var (exit, _, stderr) = await RunPromoteAsync(h, "n");

        // then: a pure no-op — nothing moved anywhere, the request survives for a later retry
        exit.Should().Be(Promoter.Exit.Denied);
        stderr.Should().Contain("Denied");
        (await h.MainHasEntryAsync("Inbox/DeniedEntry")).Should().BeFalse();
        (await h.StagedEntryPathsAsync()).Should().ContainSingle(); // staging untouched
        PendingRequest.TryLoad(h.Paths).Should().NotBeNull();        // request kept
    }

    [RequiresCliFact]
    public async Task NoPendingRequest_Refuses()
    {
        // when: promote is invoked with no pending request at all
        using var h = await VaultHarness.CreateAsync();
        var (exit, _, stderr) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);

        // then: it refuses clearly instead of prompting into a void
        exit.Should().Be(Promoter.Exit.Error);
        stderr.Should().Contain("No pending promotion request");
    }

    [RequiresCliFact]
    public async Task WrongPasswordThenEof_AbortsAsNoOp()
    {
        // given: a staged entry and a recorded request
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "Protected", "body", h.CreateAttachmentFile("y.bin", 64));
        await h.RecordPromotionRequestAsync();

        // when: the first password attempt is wrong and the second hits closed stdin
        // (EOF) — the human walked away mid-prompt
        var (exit, _, stderr) = await RunPromoteAsync(h, "y", "totally-wrong-password");

        // then: a clean no-op abort with an honest explanation; everything stays put
        exit.Should().Be(Promoter.Exit.Denied);
        stderr.Should().Contain("Attempt failed").And.Contain("Input closed at the password prompt");
        (await h.MainHasEntryAsync("Inbox/Protected")).Should().BeFalse();
        (await h.StagedEntryPathsAsync()).Should().ContainSingle();
        PendingRequest.TryLoad(h.Paths).Should().NotBeNull();
    }

    [RequiresCliFact]
    public async Task WrongThenEmptyThenCorrect_MergesOnThirdAttempt()
    {
        // given: a staged entry and a recorded request
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "Retryable", "body", h.CreateAttachmentFile("z.bin", 64));
        await h.RecordPromotionRequestAsync();

        // when: attempt 1 is wrong, attempt 2 is empty, attempt 3 is right
        var (exit, stdout, stderr) = await RunPromoteAsync(h, "y", "wrong-one", "", VaultHarness.MainPassword);

        // then: it still merges — and the failures are reported honestly, attempt by attempt
        exit.Should().Be(Promoter.Exit.Ok);
        stderr.Should().Contain("attempt 1/3").And.Contain("Empty password");
        stdout.Should().MatchRegex("Added:|Creating missing");
        (await h.MainHasEntryAsync("Inbox/Retryable")).Should().BeTrue();
        (await h.StagedEntryPathsAsync()).Should().BeEmpty();
        PendingRequest.TryLoad(h.Paths).Should().BeNull();
    }

    [RequiresCliFact]
    public async Task ThreeFailedAttempts_StopsCleanly_KeepsEverything()
    {
        // given: a staged entry and a recorded request
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "Guarded", "body", h.CreateAttachmentFile("w.bin", 64));
        await h.RecordPromotionRequestAsync();

        // when: all three password attempts are wrong
        var (exit, _, stderr) = await RunPromoteAsync(h, "y", "wrong-1", "wrong-2", "wrong-3");

        // then: it stops cleanly after the third try, counts them honestly, and keeps
        // staging + request exactly as they were
        exit.Should().Be(Promoter.Exit.Error);
        stderr.Should().Contain("attempt 3/3").And.Contain("3 password attempts failed");
        (await h.MainHasEntryAsync("Inbox/Guarded")).Should().BeFalse();
        (await h.StagedEntryPathsAsync()).Should().ContainSingle(); // staging kept
        PendingRequest.TryLoad(h.Paths).Should().NotBeNull();        // request kept
    }

    [RequiresCliFact]
    public async Task MtimeWarning_AppearsWhenMainChangedOutsideFlow()
    {
        // given: a previous promote that recorded an older mtime, then the main vault
        // file changed outside the flow — the next merge might miss someone else's edits
        using var h = await VaultHarness.CreateAsync();
        new PromoterState { LastPromotedUtc = DateTimeOffset.UtcNow.AddDays(-1), LastMainMtimeUtc = File.GetLastWriteTimeUtc(h.MainPath).AddMinutes(-30) }.Save(h.Paths);
        File.SetLastWriteTimeUtc(h.MainPath, DateTime.UtcNow.AddMinutes(5));

        await h.StageAsync("Inbox", "MtimeEntry", "body");
        await h.RecordPromotionRequestAsync();

        // when: the human approves anyway, then: the warning is in front of them —
        // the decision stays theirs, but it is never made blind
        var (_, _, stderr) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);
        stderr.Should().Contain("WARNING: main vault file changed");
    }

    [RequiresCliFact]
    public async Task VerificationFailure_WhenStagingChangedAfterRequest_KeepsEverything()
    {
        // given: a request that promises "promote Inbox/Vanishing", but between
        // vault_promote and the approval someone removes the staged entry directly
        // (keepassxc-cli rm → parked in the Recycle Bin). The merge will deliver nothing.
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "Vanishing", "body");
        await h.RecordPromotionRequestAsync();

        var rm = await h.Cli.RemoveEntryAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Vanishing");
        Assert.True(rm.Success, rm.FailureSummary);

        // when: the human approves and the merge silently delivers nothing, then:
        // post-merge verification CATCHES the gap — and staging + request stay exactly
        // as they are, so the flow can be re-run after the surprise is understood
        var (exit, _, stderr) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);

        exit.Should().Be(Promoter.Exit.Error);
        stderr.Should().Contain("verification FAILED")
            .And.Contain("entry not found after merge: Inbox/Vanishing")
            .And.Contain("Staging was NOT flushed");
        (await h.MainHasEntryAsync("Inbox/Vanishing")).Should().BeFalse();
        PendingRequest.TryLoad(h.Paths).Should().NotBeNull();        // request kept
        var raw = await h.Cli.ListEntryPathsAsync(h.StagingPath, VaultHarness.StagingPassword, null);
        raw.Should().Contain(p => p.Contains("Vanishing"));          // staging kept (entry sits parked)
    }

    [RequiresCliFact]
    public async Task SecondPromote_WarnsOnExternalEdits_AndKeepsThem()
    {
        // given/when: the multi-day case — first promote (no prior state → the honest
        // note), then the user edits the main vault outside this flow ("GUI")
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "First", "original");
        await h.RecordPromotionRequestAsync();
        var (exit1, _, stderr1) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);
        exit1.Should().Be(Promoter.Exit.Ok);
        stderr1.Should().Contain("no previous promote is recorded");

        var edit = await h.Cli.EditNotesAsync(h.MainPath, VaultHarness.MainPassword, null, "Inbox/First", "edited in the GUI after promote");
        Assert.True(edit.Success, edit.FailureSummary);

        // when: new content is staged and a second promote runs, then: the approver is
        // warned about the external edits, the merge is safe, and BOTH survive —
        // the GUI edit and the newly promoted entry
        await h.StageAsync("Inbox", "Second", "new content");
        await h.RecordPromotionRequestAsync();
        var (exit2, _, stderr2) = await RunPromoteAsync(h, "y", VaultHarness.MainPassword);

        stderr2.Should().Contain("main vault file changed since the last promote");
        exit2.Should().Be(Promoter.Exit.Ok);
        var show = ShowParser.Parse(await h.ShowMainAsync("Inbox/First"));
        show.Notes.Should().Contain("edited in the GUI after promote");   // external edit survives the merge
        (await h.MainHasEntryAsync("Inbox/Second")).Should().BeTrue();    // and the new content landed
    }
}
