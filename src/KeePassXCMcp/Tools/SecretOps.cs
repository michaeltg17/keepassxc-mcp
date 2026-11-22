using System.Text.Json;
using KeePassXCMcp.Infra;

namespace KeePassXCMcp.Tools;

public sealed record SecretReceipt(string Entry, string Uuid, string Origin, int Length, string FingerprintSha256, string AtUtc);

/// <summary>Shared secret-into-vault operations (SPEC.md F1/F2/F3/F10), used by both the
/// MCP tools and the CLI verbs — same behavior over both entry points.
///
/// Generation always happens INSIDE keepassxc-cli (`add -g` / `edit -g`); values to store
/// arrive via stdin (`add -p` / `edit -p`). The values do pass through this process's
/// memory for one purpose only: computing the sha256 fingerprint for the provenance
/// sidecar. They are never returned in any receipt.</summary>
public static class SecretOps
{
    public static void ValidateValue(string value)
    {
        if (string.IsNullOrEmpty(value))
            throw new ArgumentException("the secret value must not be empty.");
        if (value.Contains('\r') || value.Contains('\n'))
            throw new ArgumentException("the secret value must be a single line (no newlines) — it travels via stdin line protocol.");
    }

    public static (string? Group, string Title) SplitLabel(string label)
    {
        var idx = label.LastIndexOf('/');
        var group = idx < 0 ? null : label[..idx];
        var title = idx < 0 ? label : label[(idx + 1)..];
        title = StagingOps.ValidateSegment(title, "title");
        group = string.IsNullOrWhiteSpace(group) ? null
            : string.Join('/', group.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(g => StagingOps.ValidateSegment(g, "group")));
        return (group, title);
    }

    /// <summary>F1: generate a new password inside keepassxc-cli and stage it. The value
    /// never enters this conversation; the caller only ever gets the receipt.</summary>
    public static async Task<SecretReceipt> GenerateAsync(
        VaultConfig cfg, ConfigPaths paths, KeePassCli cli, StagingMaintenance staging,
        string label, GenProfile profile, string? notes = null,
        CancellationToken ct = default)
    {
        var (group, title) = SplitLabel(label);
        await PrepareStagingAsync(cfg, cli, staging, group, ct);
        var entryPath = StagingOps.BuildEntryPath(group, title);

        var add = await cli.AddGeneratedAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, profile, notes, ct);
        if (!add.Success)
        {
            if (add.StdErr.Contains("Could not create entry", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"An entry already exists at '{entryPath}'. Use vault_rotate to replace its password.");
            throw new KeePassCliException("add -g failed: " + Redact.Apply(add.FailureSummary, cfg.KnownSecrets));
        }

        var (uuid, fingerprint) = await FingerprintAsync(cfg, cli, entryPath, ct);
        RecordProvenance(paths, entryPath, uuid, Origin.Generated, fingerprint, rotated: false);
        return new SecretReceipt(entryPath, uuid, Origin.Generated, profile.Length, fingerprint, DateTimeOffset.UtcNow.ToString("O"));
    }

    /// <summary>F2/F3: store a value supplied by the caller (origin says how it got here:
    /// piped via CLI stdin, or seen-by-model via the MCP tool).</summary>
    public static async Task<SecretReceipt> StageValueAsync(
        VaultConfig cfg, ConfigPaths paths, KeePassCli cli, StagingMaintenance staging,
        string label, string value, string origin,
        string? notes = null, string? username = null, string? url = null,
        CancellationToken ct = default)
    {
        ValidateValue(value);
        if (origin is not (Origin.Piped or Origin.SeenByModel))
            throw new ArgumentException($"origin must be '{Origin.Piped}' or '{Origin.SeenByModel}'.");

        var (group, title) = SplitLabel(label);
        await PrepareStagingAsync(cfg, cli, staging, group, ct);
        var entryPath = StagingOps.BuildEntryPath(group, title);

        var add = await cli.AddWithValueAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, value, notes, username, url, ct);
        bool preexisted;
        if (add.Success) preexisted = false;
        else if (add.StdErr.Contains("Could not create entry", StringComparison.OrdinalIgnoreCase) && add.StdOut.Length == 0)
        {
            preexisted = true;
            var edit = await cli.EditWithValueAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, value, notes, username, url, ct);
            if (!edit.Success)
                throw new KeePassCliException("edit -p failed: " + Redact.Apply(edit.FailureSummary, cfg.KnownSecrets));
        }
        else
        {
            throw new KeePassCliException("add -p failed: " + Redact.Apply(add.FailureSummary, cfg.KnownSecrets));
        }

        var (uuid, fingerprint) = await FingerprintAsync(cfg, cli, entryPath, ct);
        RecordProvenance(paths, entryPath, uuid, origin, fingerprint, rotated: preexisted);
        return new SecretReceipt(entryPath, uuid, origin, value.Length, fingerprint, DateTimeOffset.UtcNow.ToString("O"));
    }

    /// <summary>F10: rotate a STAGED entry's password (regenerated inside keepassxc-cli).
    /// Main-vault rotation runs through the promote flow: rotate the staged entry, or
    /// generate a replacement and promote it. Returns the new fingerprint.</summary>
    public static async Task<SecretReceipt> RotateAsync(
        VaultConfig cfg, ConfigPaths paths, KeePassCli cli, StagingMaintenance staging,
        string label, GenProfile profile,
        CancellationToken ct = default)
    {
        var (group, title) = SplitLabel(label);
        var entryPath = StagingOps.BuildEntryPath(group, title);
        await staging.EnsureStagingAsync(ct);

        var probe = await cli.ShowRawAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, ct: ct);
        if (!probe.Success)
            throw new InvalidOperationException($"'{entryPath}' is not in staging. Rotation always happens on the staged copy: stage the entry (or regenerate it), rotate, then promote — the human gate is never bypassed.");

        var edit = await cli.EditGeneratedAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, profile, ct);
        if (!edit.Success)
            throw new KeePassCliException("edit -g failed: " + Redact.Apply(edit.FailureSummary, cfg.KnownSecrets));

        var (uuid, fingerprint) = await FingerprintAsync(cfg, cli, entryPath, ct);
        RecordProvenance(paths, entryPath, uuid, Origin.Generated, fingerprint, rotated: true);
        return new SecretReceipt(entryPath, uuid, Origin.Generated, profile.Length, fingerprint, DateTimeOffset.UtcNow.ToString("O"));
    }

    private static async Task PrepareStagingAsync(VaultConfig cfg, KeePassCli cli, StagingMaintenance staging, string? group, CancellationToken ct)
    {
        await staging.EnsureStagingAsync(ct);
        if (!string.IsNullOrEmpty(group))
            await cli.EnsureGroupAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, group, ct);
    }

    /// <summary>UUID + fingerprint by reading the entry back from STAGING (its password is
    /// a config secret by design — staging is not a confidentiality boundary, see SECURITY.md).</summary>
    private static async Task<(string Uuid, string Fingerprint)> FingerprintAsync(VaultConfig cfg, KeePassCli cli, string entryPath, CancellationToken ct)
    {
        var show = ShowParser.Parse((await cli.ShowAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, showAttachments: false, ct: ct)).StdOut);
        var value = await cli.ReadAttributeAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, entryPath, "Password", ct);
        return (show.Uuid, Hashing.Sha256Hex(value));
    }

    private static void RecordProvenance(ConfigPaths paths, string entryPath, string uuid, string origin, string fingerprint, bool rotated)
    {
        var store = ProvenanceStore.Load(paths);
        store.Upsert(entryPath, string.IsNullOrEmpty(uuid) ? null : uuid, origin, fingerprint, rotated);
        store.Save(paths);
    }

    public static string ToJson(object value) => JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true });
}
