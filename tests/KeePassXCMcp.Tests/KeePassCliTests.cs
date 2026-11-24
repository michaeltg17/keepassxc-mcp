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
        Assert.Empty(await h.StagedEntryPathsAsync());

        await h.Staging.EnsureStagingAsync();
        await h.Cli.EnsureGroupAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Nested");
        var add = await h.Cli.AddEntryAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Nested/Alpha", "line one\nline two");
        Assert.True(add.Success, add.FailureSummary);

        var entries = await h.StagedEntryPathsAsync();
        Assert.Contains("Inbox/Nested/Alpha", entries);

        var show = await h.Cli.ShowAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Inbox/Nested/Alpha");
        var parsed = ShowParser.Parse(show.StdOut);
        Assert.Equal("Alpha", parsed.Title);
        Assert.Equal("line one\nline two", parsed.Notes);
    }

    [RequiresCliFact]
    public async Task AttachmentRoundTrip_HashMatchesStored()
    {
        using var h = await VaultHarness.CreateAsync();
        var source = h.CreateAttachmentFile("report.bin", 4096);
        var sourceSha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(source)));

        var (entry, attachments) = await h.StageAsync("Inbox", "WithFile", "notes body", source);
        Assert.Equal("Inbox/WithFile", entry);
        var a = Assert.Single(attachments);
        Assert.Equal("report.bin", a.Name);
        Assert.Equal(4096, a.Size);
        Assert.Equal(sourceSha, a.Sha256);
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
        Assert.Matches("Added:|Creating missing", dry.StdOut);
        Assert.False(await h.MainHasEntryAsync("Inbox/ToMerge"), "dry-run must not modify the main vault");
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

        Assert.True(await h.MainHasEntryAsync(entry));
        var show = ShowParser.Parse(await h.ShowMainAsync(entry));
        var stored = Assert.Single(show.Attachments);
        Assert.Equal("doc.pdf", stored.Name);
        var (sha, size) = await StagingOps.HashStoredAttachmentAsync(
            h.Config, h.Cli, h.MainPath, VaultHarness.MainPassword, h.MainHasKeyfile ? h.KeyfilePath : null, entry, "doc.pdf");
        Assert.Equal(attachments[0].Sha256, sha);
        Assert.Equal(2048, size);
    }

    [RequiresCliFact]
    public async Task KeyfileVault_RequiresBothCredentialsInOneInvocation()
    {
        using var h = await VaultHarness.CreateAsync(mainWithKeyfile: true);
        // password only (no -k) must fail...
        var noKeyfile = await h.Cli.ShowRawAsync(h.MainPath, VaultHarness.MainPassword, null, "anything");
        Assert.False(noKeyfile.Success);
        // ...and -k + password in one call must work (empty listing succeeds).
        var ls = await h.Cli.ListEntryPathsAsync(h.MainPath, VaultHarness.MainPassword, h.KeyfilePath);
        Assert.NotNull(ls);
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

        Assert.Contains("Keep/Me", paths);
        Assert.DoesNotContain(paths, p => p.Contains("[empty]"));
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
        Assert.Equal("Note", parsed.Title);
        Assert.Equal("first line\n  second line", parsed.Notes);
        Assert.Equal(2, parsed.Attachments.Count);
        Assert.Equal(("payload.txt", 16L), (parsed.Attachments[0].Name, parsed.Attachments[0].SizeBytes));
        Assert.Equal(("big.bin", 1536L), (parsed.Attachments[1].Name, parsed.Attachments[1].SizeBytes));
    }
}
