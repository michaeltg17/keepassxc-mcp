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
        using var h = await VaultHarness.CreateAsync();
        (await h.StagedEntryPathsAsync()).Should().BeEmpty();

        await h.Staging.EnsureStagingAsync();
        await h.Cli.EnsureGroupAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Nested");
        var add = await h.Cli.AddEntryAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Nested/Alpha", "line one\nline two");
        Assert.True(add.Success, add.FailureSummary);

        var entries = await h.StagedEntryPathsAsync();
        entries.Should().Contain("Inbox/Nested/Alpha");

        var show = await h.Cli.ShowAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Nested/Alpha");
        var parsed = ShowParser.Parse(show.StdOut);
        parsed.Title.Should().Be("Alpha");
        parsed.Notes.Should().Be("line one\nline two");
    }

    [RequiresCliFact]
    public async Task AttachmentRoundTrip_HashMatchesStored()
    {
        using var h = await VaultHarness.CreateAsync();
        var source = h.CreateAttachmentFile("report.bin", 4096);
        var sourceSha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(source)));

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
        using var h = await VaultHarness.CreateAsync();
        var source = h.CreateAttachmentFile("payload.txt", 256);
        await h.StageAsync("Inbox", "ToMerge", "body", source);

        var dry = await h.Cli.MergeAsync(h.MainPath, VaultHarness.MainPassword, null, h.StagingPath, VaultHarness.StagingPassword, dryRun: true);
        Assert.True(dry.Success, dry.FailureSummary);
        // keepassxc-cli wording varies by version ("Added: …" / "Creating missing …").
        dry.StdOut.Should().MatchRegex("Added:|Creating missing");
        (await h.MainHasEntryAsync("Inbox/ToMerge")).Should().BeFalse("dry-run must not modify the main vault");
    }

    [RequiresCliTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Merge_Then_VerifyAttachments(bool mainWithKeyfile)
    {
        using var h = await VaultHarness.CreateAsync(mainWithKeyfile);
        var source = h.CreateAttachmentFile("doc.pdf", 2048);
        var (entry, attachments) = await h.StageAsync("Reports/Q1", "Doc", "pdf body", source);

        var merge = await h.Cli.MergeAsync(h.MainPath, VaultHarness.MainPassword, h.MainHasKeyfile ? h.KeyfilePath : null,
            h.StagingPath, VaultHarness.StagingPassword, dryRun: false);
        Assert.True(merge.Success, merge.FailureSummary);

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
        using var h = await VaultHarness.CreateAsync(mainWithKeyfile: true);
        // password only (no -k) must fail...
        var noKeyfile = await h.Cli.ShowRawAsync(h.MainPath, VaultHarness.MainPassword, null, "anything");
        noKeyfile.Success.Should().BeFalse();
        // ...and -k + password in one call must work: the listing itself succeeds and is empty.
        var ls = await h.Cli.ListEntryPathsAsync(h.MainPath, VaultHarness.MainPassword, h.KeyfilePath);
        ls.Should().BeEmpty();
    }

    [RequiresCliFact]
    public async Task ListEntryPaths_SkipsEmptyGroupSentinels()
    {
        // keepassxc-cli marks empty groups with a "[empty]" line (bare for a wholly empty
        // db, prefixed "Group/[empty]" otherwise). Neither is an entry. Regression: 0.3.0
        // beta parsed "Recycle Bin/[empty]" as a staged entry.
        using var h = await VaultHarness.CreateAsync();
        await h.Cli.EnsureGroupAsync(h.MainPath, VaultHarness.MainPassword, null, "Keep");
        var add = await h.Cli.AddEntryAsync(h.MainPath, VaultHarness.MainPassword, null, "Keep/Me", "note");
        Assert.True(add.Success, add.FailureSummary);
        await h.Cli.EnsureGroupAsync(h.MainPath, VaultHarness.MainPassword, null, "EmptyGroup");

        var paths = await h.Cli.ListEntryPathsAsync(h.MainPath, VaultHarness.MainPassword, null);

        paths.Should().Contain("Keep/Me").And.NotContain(p => p.Contains("[empty]"));
    }

    [Fact]
    public void ShowParser_ParsesMultiLineNotesAndAttachments()
    {
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
        parsed.Title.Should().Be("Note");
        parsed.Notes.Should().Be("first line\n  second line");
        parsed.Attachments.Should().HaveCount(2);
        parsed.Attachments.Select(a => (a.Name, a.SizeBytes)).Should()
            .Equal(("payload.txt", 16L), ("big.bin", 1536L)); // ordered sequence equality
    }
}
