using System.Security.Cryptography;
using KeePassXCMcp.Infra;
using KeePassXCMcp.Tools;

namespace KeePassXCMcp.Tests;

/// <summary>KeePassCli wrapper integration tests against throwaway kdbx databases —
/// the spike's guarantees (stdin passwords, keyfile combo, attachment round-trip) as tests.</summary>
public class KeePassCliTests
{
    [RequiresCliFact]
    public async Task DbCreate_Then_ListAndAddEntry_ShowRoundTrip()
    {
        // given: a freshly created staging database with no entries at all
        using var h = await VaultHarness.CreateAsync();
        (await h.StagedEntryPathsAsync()).Should().BeEmpty();

        // when: a nested group and an entry with multi-line notes are created through
        // the CLI wrapper (password on stdin, never on the command line)
        await h.Staging.EnsureStagingAsync();
        await h.Cli.EnsureGroupAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Nested");
        var add = await h.Cli.AddEntryAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Nested/Alpha", "line one\nline two");
        Assert.True(add.Success, add.FailureSummary);

        // then: the flat recursive listing finds it…
        var entries = await h.StagedEntryPathsAsync();
        entries.Should().Contain("Inbox/Nested/Alpha");

        // …and `show` round-trips: title exact, notes exactly as written, lines intact
        var show = await h.Cli.ShowAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Nested/Alpha");
        var parsed = ShowParser.Parse(show.StdOut);
        parsed.Title.Should().Be("Alpha");
        parsed.Notes.Should().Be("line one\nline two");
    }

    [RequiresCliFact]
    public async Task AttachmentRoundTrip_HashMatchesStored()
    {
        // given: a 4 KiB file and its independently computed sha256
        using var h = await VaultHarness.CreateAsync();
        var source = h.CreateAttachmentFile("report.bin", 4096);
        var sourceSha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(source)));

        // when: an entry with that attachment is staged into the sandbox, then: the
        // receipt states exactly the file that went in — name, size, and content hash
        var (entry, attachments) = await h.StageAsync("Inbox", "WithFile", "notes body", source);
        entry.Should().Be("Inbox/WithFile");
        var a = Assert.Single(attachments);
        a.Name.Should().Be("report.bin");
        a.Size.Should().Be(4096);
        a.Sha256.Should().Be(sourceSha);
    }

    [RequiresCliFact]
    public async Task MergeDryRun_PredictsAdds_WithoutTouchingMain()
    {
        // given: staged content (entry + attachment) awaiting promotion
        using var h = await VaultHarness.CreateAsync();
        var source = h.CreateAttachmentFile("payload.txt", 256);
        await h.StageAsync("Inbox", "ToMerge", "body", source);

        // when: merge --dry-run is asked what it WOULD do, then: the diff predicts the
        // add (wording varies by CLI version)…
        var dry = await h.Cli.MergeAsync(h.MainPath, VaultHarness.MainPassword, null, h.StagingPath, VaultHarness.StagingPassword, dryRun: true);
        Assert.True(dry.Success, dry.FailureSummary);
        dry.StdOut.Should().MatchRegex("Added:|Creating missing");

        // …and main is untouched — a preview must never be a mutation
        (await h.MainHasEntryAsync("Inbox/ToMerge")).Should().BeFalse("dry-run must not modify the main vault");
    }

    [RequiresCliTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Merge_Then_VerifyAttachments(bool mainWithKeyfile)
    {
        // given: a staged PDF, and a main vault that is password-only or password+keyfile
        using var h = await VaultHarness.CreateAsync(mainWithKeyfile);
        var source = h.CreateAttachmentFile("doc.pdf", 2048);
        var (entry, attachments) = await h.StageAsync("Reports/Q1", "Doc", "pdf body", source);

        // when: the merge runs for real (the keyfile variant must work in one invocation)
        var merge = await h.Cli.MergeAsync(h.MainPath, VaultHarness.MainPassword, h.MainHasKeyfile ? h.KeyfilePath : null,
            h.StagingPath, VaultHarness.StagingPassword, dryRun: false);
        Assert.True(merge.Success, merge.FailureSummary);

        // then: main holds the entry, its attachment is intact — exactly one, right name —
        // and re-hashing what is STORED in main matches the hash staged promised
        (await h.MainHasEntryAsync(entry)).Should().BeTrue();
        var show = ShowParser.Parse(await h.ShowMainAsync(entry));
        var stored = Assert.Single(show.Attachments);
        stored.Name.Should().Be("doc.pdf");
        var (sha, size) = await StagingOps.HashStoredAttachmentAsync(
            h.Config, h.Cli, h.MainPath, VaultHarness.MainPassword, h.MainHasKeyfile ? h.KeyfilePath : null, entry, "doc.pdf");
        sha.Should().Be(attachments[0].Sha256);
        size.Should().Be(2048);
    }

    [RequiresCliFact]
    public async Task KeyfileVault_RequiresBothCredentialsInOneInvocation()
    {
        // given: a main vault protected by password AND keyfile
        using var h = await VaultHarness.CreateAsync(mainWithKeyfile: true);

        // when: it is opened with the password only (no -k), then: it cannot be opened
        var noKeyfile = await h.Cli.ShowRawAsync(h.MainPath, VaultHarness.MainPassword, null, "anything");
        noKeyfile.Success.Should().BeFalse();

        // when: both credentials arrive in ONE invocation, then: it opens — the empty
        // listing succeeds and really is empty
        var ls = await h.Cli.ListEntryPathsAsync(h.MainPath, VaultHarness.MainPassword, h.KeyfilePath);
        ls.Should().BeEmpty();
    }

    [RequiresCliFact]
    public async Task ListEntryPaths_SkipsEmptyGroupSentinels()
    {
        // given: a database with one entry, one empty group — so keepassxc-cli's
        // "[empty]" sentinel appears in the listing (bare for a wholly empty db,
        // prefixed "Group/[empty]" otherwise; neither is an entry. Regression: 0.3.0
        // beta parsed "Recycle Bin/[empty]" as a staged entry)
        using var h = await VaultHarness.CreateAsync();
        await h.Cli.EnsureGroupAsync(h.MainPath, VaultHarness.MainPassword, null, "Keep");
        var add = await h.Cli.AddEntryAsync(h.MainPath, VaultHarness.MainPassword, null, "Keep/Me", "note");
        Assert.True(add.Success, add.FailureSummary);
        await h.Cli.EnsureGroupAsync(h.MainPath, VaultHarness.MainPassword, null, "EmptyGroup");

        // when: the flat recursive listing is parsed, then: the real entry is there and
        // no sentinel ever looks like an entry
        var paths = await h.Cli.ListEntryPathsAsync(h.MainPath, VaultHarness.MainPassword, null);
        paths.Should().Contain("Keep/Me").And.NotContain(p => p.Contains("[empty]"));
    }

    [Fact]
    public void ShowParser_ParsesMultiLineNotesAndAttachments()
    {
        // given: real `keepassxc-cli show` output with multi-line notes and two attachments
        var parsed = ShowParser.Parse("""
            Title: Note
            UserName:
            Password: PROTECTED
            URL:
            Notes: first line
              second line
            Uuid: {11885d0e-7cb6-4a90-be69-bce2d32da693}
            Tags:

            Attachments:
              payload.txt (16 B)
              big.bin (1.5 KiB)
            """);

        // when: it is parsed, then: the title is exact, the notes keep their lines and
        // indentation, and both attachments survive in order with their sizes
        parsed.Title.Should().Be("Note");
        parsed.Notes.Should().Be("first line\n  second line");
        parsed.Attachments.Should().HaveCount(2);
        parsed.Attachments.Select(a => (a.Name, a.SizeBytes)).Should()
            .Equal(("payload.txt", 16L), ("big.bin", 1536L)); // ordered sequence equality
    }
}
