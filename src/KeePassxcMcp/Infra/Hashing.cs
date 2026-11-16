using System.Security.Cryptography;

namespace KeePassxcMcp.Infra;

public static class Hashing
{
    /// <summary>sha256 (lowercase hex) + size of a file on disk.</summary>
    public static async Task<(string Sha256, long Size)> Sha256FileAsync(string path, CancellationToken ct = default)
    {
        await using var fs = File.OpenRead(path);
        using var sha = SHA256.Create();
        var hash = await sha.ComputeHashAsync(fs, ct);
        return (Convert.ToHexStringLower(hash), new FileInfo(path).Length);
    }
}
