using System.Security.Cryptography;
using System.Text;

namespace KeePassXCMcp.Infra;

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

    /// <summary>sha256 (lowercase hex) of UTF-8 text. Used ONLY to derive non-reversible
    /// fingerprints for the provenance sidecar (SPEC.md E3) — the sidecar never stores
    /// the value itself, and the fingerprint is never used for equality of secrets
    /// across trust boundaries (it is a rotation-tracking hint, not a MAC).</summary>
    public static string Sha256Hex(string text)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexStringLower(sha.ComputeHash(Encoding.UTF8.GetBytes(text)));
    }
}
