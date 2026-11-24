using System.Text.Json;
using KeePassXCMcp.Infra;

namespace KeePassXCMcp.Tools;

public sealed record AttachmentReceipt(string Name, long Bytes, string Sha256, bool SourceMatches);

public sealed record StageReceipt(string Entry, bool EntryPreexisted, IReadOnlyList<AttachmentReceipt> Attachments, string StagedAtUtc);

/// <summary>Receipt for a discarded staged entry. The disposition is always "recycled":
/// keepassxc-cli `rm` parks the entry in the staging database's Recycle Bin and there is
/// no CLI purge — recovery is the KeePassXC GUI. That is safe by design: staging is not a
/// confidentiality boundary (SECURITY.md), so a recycled staged entry leaks nothing a
/// staged entry wasn't already exposed as.</summary>
public sealed record StagedRemovalReceipt(string Entry, string Disposition, string RecoverVia, string RemovedAtUtc);

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

    /// <summary>Discard one STAGED entry before promote (the F-flow's delete half). Pure
    /// label operation — no secret value is read anywhere in this flow. `rm -q` parks the
    /// entry in the staging database's Recycle Bin (the CLI has no purge; recovery is the
    /// KeePassXC GUI). Verify-after-write mirrors the promote flow: rm exit 0 AND the entry
    /// gone from the active listing. Sidecars on success only: the manifest record is
    /// dropped and the provenance record removed — so neither can go stale.</summary>
    public static async Task<StagedRemovalReceipt> RemoveStagedAsync(
        VaultConfig cfg, ConfigPaths paths, KeePassCli cli, StagingMaintenance staging,
        string entryPath, string confirm, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(entryPath))
            throw new ArgumentException("entryPath must not be empty.");

        var staged = await staging.ListEntryPathsAsync(ct);
        if (!staged.Contains(entryPath))
            throw new InvalidOperationException(
                $"'{entryPath}' is not in staging. Nothing changed. Current staged entries:\n{ToJson(staged)}");

        // The only friction knob: the caller must repeat the exact path.
        if (confirm != entryPath)
            throw new ArgumentException($"confirmation does not match — pass the exact entry path ('{entryPath}') as confirm to remove it. Nothing changed.");

        var rm = await cli.RemoveEntryAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, ct);
        if (!rm.Success)
            throw new KeePassCliException("rm failed: " + Redact.Apply(rm.FailureSummary, cfg.KnownSecrets));

        // Post-removal verification: gone from the ACTIVE listing (recycled entries are
        // invisible to ls by design — StagingMaintenance.ListEntryPathsAsync filters them).
        var after = await staging.ListEntryPathsAsync(ct);
        if (after.Contains(entryPath))
            throw new KeePassCliException($"Removal verification failed: '{entryPath}' is still in the staged listing.");

        DropManifestRecord(paths, entryPath);
        var provenance = ProvenanceStore.Load(paths);
        if (provenance.Remove(entryPath)) provenance.Save(paths);

        return new StagedRemovalReceipt(entryPath, "recycled",
            "KeePassXC GUI → open the staging database and restore it from the Recycle Bin",
            DateTimeOffset.UtcNow.ToString("O"));
    }

    /// <summary>Drop an entry (and its attachments) from the pending promotion request, if
    /// one exists — the same manifest the approver reviews must not advertise a removed entry.</summary>
    private static void DropManifestRecord(ConfigPaths paths, string entryPath)
    {
        var pending = PendingRequest.TryLoad(paths);
        if (pending is null) return;
        var dropped = pending.Entries.RemoveAll(e => e.Path == entryPath)
                    + pending.Attachments.RemoveAll(a => a.EntryPath == entryPath);
        if (dropped > 0) PendingRequest.Save(paths, pending);
    }

    public static string ToJson(object value) => JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true });
}
