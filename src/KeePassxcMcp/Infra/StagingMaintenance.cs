namespace KeePassxcMcp.Infra;

/// <summary>Staging-database lifecycle: creation, listing, post-merge flush.
/// Flush = delete + re-create with the config password (kdbx can't have no credentials),
/// which guarantees no stale entries and no merge history bloat.</summary>
public sealed class StagingMaintenance(KeePassCli cli, VaultConfig cfg)
{
    public async Task EnsureStagingAsync(CancellationToken ct = default)
    {
        if (File.Exists(cfg.StagingVaultPath)) return;
        var dir = Path.GetDirectoryName(Path.GetFullPath(cfg.StagingVaultPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        await cli.DbCreateAsync(cfg.StagingVaultPath, cfg.StagingPassword, ct: ct);
    }

    public async Task FlushAsync(CancellationToken ct = default)
    {
        if (File.Exists(cfg.StagingVaultPath)) File.Delete(cfg.StagingVaultPath);
        await EnsureStagingAsync(ct);
    }

    public Task<IReadOnlyList<string>> ListEntryPathsAsync(CancellationToken ct = default)
        => cli.ListEntryPathsAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, ct);
}
