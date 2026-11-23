namespace KeePassXCMcp.Infra;

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

    /// <summary>Staged content = every entry EXCEPT the Recycle Bin's. keepassxc-cli's `rm`
    /// parks deleted entries there (a human tidying staging does exactly that), and a parked
    /// entry is by definition NOT staged: listing it would put it in the promotion request,
    /// where the merge never brings it across and post-merge verification fails on it
    /// (0.3.0 beta drill).</summary>
    public async Task<IReadOnlyList<string>> ListEntryPathsAsync(CancellationToken ct = default)
    {
        var all = await cli.ListEntryPathsAsync(cfg.StagingVaultPath, cfg.StagingPassword, null, ct);
        return all.Where(p => !IsRecycled(p)).ToList();
    }

    private static bool IsRecycled(string path) =>
        path.StartsWith(RecycleBinGroupName + "/", StringComparison.OrdinalIgnoreCase);

    /// <summary>kdbx identifies the recycle bin by group UUID; keepassxc-cli's listing only
    /// exposes its default name, which is what any `rm` creates.</summary>
    public const string RecycleBinGroupName = "Recycle Bin";
}
