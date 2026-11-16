using System.Text.Json;
using KeePassxcMcp.Infra;

namespace KeePassxcMcp.Tools;

public sealed record AttachmentReceipt(string Name, long Bytes, string Sha256, bool SourceMatches);

public sealed record StageReceipt(string Entry, bool EntryPreexisted, IReadOnlyList<AttachmentReceipt> Attachments, string StagedAtUtc);

public sealed record SnapshotEntry(string Path, string Group, string Title, string Notes, IReadOnlyList<StagedAttachmentInfo> Attachments);

public sealed record StagingSnapshot(DateTimeOffset SnapshotAtUtc, IReadOnlyList<SnapshotEntry> Entries);

/// <summary>Staging operations shared by the MCP tools (and the test harness).
/// Everything here talks ONLY to the staging database from config.</summary>
public static class StagingOps
{
    public static string ValidateSegment(string value, string what)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0) throw new ArgumentException($"{what} must not be empty.");
        if (trimmed.Contains('/') || trimmed == "." || trimmed == "..")
            throw new ArgumentException($"{what} must not contain '/' or path segments (got '{value}'). Use nested groups via the group parameter.");
        if (trimmed.Any(char.IsControl)) throw new ArgumentException($"{what} must not contain control characters.");
        return trimmed;
    }

    public static string BuildEntryPath(string? group, string title) =>
        string.IsNullOrWhiteSpace(group) ? title : group.Trim('/') + "/" + title;

    /// <summary>add (or edit notes if the entry already exists) + attachment-import (-f),
    /// then VERIFY by reading the entry back with show --show-attachments and re-hashing
    /// each attachment as it is actually stored in the staging database.</summary>
    public static async Task<StageReceipt> StageEntryAsync(
        VaultConfig cfg, KeePassCli cli, StagingMaintenance staging,
        string? group, string title, string? notes, IReadOnlyList<string>? files,
        CancellationToken ct = default)
    {
        var safeTitle = ValidateSegment(title, "title");
        var safeGroup = group is null ? null : string.Join('/', group.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(g => ValidateSegment(g, "group")));
        notes ??= "";

        await staging.EnsureStagingAsync(ct);
        if (!string.IsNullOrEmpty(safeGroup))
            await cli.EnsureGroupAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, safeGroup, ct);

        var entryPath = BuildEntryPath(safeGroup, safeTitle);
        var add = await cli.AddEntryAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, notes, ct);
        bool preexisted;
        if (add.Success) preexisted = false;
        else if (add.StdErr.Contains("Could not create entry", StringComparison.OrdinalIgnoreCase)
              && add.StdOut.Length == 0)
        {
            preexisted = true;
            await cli.EditNotesAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, notes, ct);
        }
        else
        {
            throw new KeePassCliException("add failed: " + Redact.Apply(add.FailureSummary, cfg.KnownSecrets));
        }

        var receipts = new List<AttachmentReceipt>();
        foreach (var source in files ?? [])
        {
            if (!File.Exists(source))
                throw new ArgumentException($"Attachment source file not found: {source}");
            var name = Path.GetFileName(source);
            await cli.ImportAttachmentAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, name, source, ct);

            var (sourceSha, sourceSize) = await Hashing.Sha256FileAsync(source, ct);
            var (storedSha, storedSize) = await HashStoredAttachmentAsync(cfg, cli, cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, name, ct);
            receipts.Add(new AttachmentReceipt(name, storedSize, storedSha,
                SourceMatches: storedSha == sourceSha && storedSize == sourceSize));
        }

        // Final readback verification.
        var show = ShowParser.Parse((await cli.ShowAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, ct: ct)).StdOut);
        if (show.Title != safeTitle || receipts.Any(r => show.Attachments.All(a => a.Name != r.Name)))
            throw new KeePassCliException($"Staging verification failed for {entryPath}.");

        return new StageReceipt(entryPath, preexisted, receipts, DateTimeOffset.UtcNow.ToString("O"));
    }

    /// <summary>Export an attachment from a database to a temp file and hash what is actually stored.</summary>
    public static async Task<(string Sha256, long Size)> HashStoredAttachmentAsync(
        VaultConfig cfg, KeePassCli cli, string dbPath, string password, string? keyfile,
        string entryPath, string attachmentName, CancellationToken ct = default)
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"kpxc-mcp-verify-{Guid.NewGuid():N}");
        try
        {
            await cli.ExportAttachmentAsync(dbPath, password, keyfile, entryPath, attachmentName, tmp, ct);
            return await Hashing.Sha256FileAsync(tmp, ct);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    /// <summary>Full snapshot of staging: entries, notes, and per-attachment name/size/sha256
    /// as actually stored in the staging kdbx.</summary>
    public static async Task<StagingSnapshot> SnapshotStagingAsync(VaultConfig cfg, KeePassCli cli, StagingMaintenance staging, CancellationToken ct = default)
    {
        await staging.EnsureStagingAsync(ct);
        var paths = await staging.ListEntryPathsAsync(ct);
        var entries = new List<SnapshotEntry>();
        foreach (var entryPath in paths)
        {
            var show = ShowParser.Parse((await cli.ShowAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, ct: ct)).StdOut);
            var attachments = new List<StagedAttachmentInfo>();
            foreach (var a in show.Attachments)
            {
                var (sha, size) = await HashStoredAttachmentAsync(cfg, cli, cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, a.Name, ct);
                attachments.Add(new StagedAttachmentInfo(entryPath, a.Name, size, sha));
            }
            var idx = entryPath.LastIndexOf('/');
            entries.Add(new SnapshotEntry(entryPath, idx < 0 ? "" : entryPath[..idx], idx < 0 ? entryPath : entryPath[(idx + 1)..], show.Notes, attachments));
        }
        return new StagingSnapshot(DateTimeOffset.UtcNow, entries);
    }

    public static string ToJson(object value) => JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true });
}
