using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeePassXCMcp.Infra;

/// <summary>How a value got into the vault (SPEC.md E3). This is the whole point of the
/// sidecar: `generated`/`piped` values were never visible to any model; `seen-by-model`
/// values must be surfaced for rotation at end of task (P1: security before automation).</summary>
public static class Origin
{
    public const string Generated = "generated"; // created by keepassxc-cli's generator (F1/F10)
    public const string Piped = "piped";         // flowed via stdin into `stage` (F2.1)
    public const string SeenByModel = "seen-by-model"; // passed through agent context (F2.2/F3)
}

public sealed class ProvenanceRecord
{
    public string Path { get; set; } = "";             // entry path, the label (stable across promote)
    public string? Uuid { get; set; }                  // preserved by merge (verified) — corroborates renames
    public string Origin { get; set; } = "";
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset LastChangedUtc { get; set; }
    public string? FingerprintSha256 { get; set; }     // sha256 of the value — never the value itself
    public List<string> RetiredFingerprints { get; set; } = [];
}

/// <summary>The exposure sidecar (SPEC.md E3 / INV-D): paths, UUIDs, origins, timestamps
/// and fingerprints — NEVER secret values. Disposable by design: the user may delete the
/// file at any time; the worst case is an empty audit list (rotate-manually fallback).</summary>
public sealed class ProvenanceStore
{
    public int Version { get; set; } = 1;
    public List<ProvenanceRecord> Records { get; set; } = [];

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static ProvenanceStore Load(ConfigPaths paths) =>
        File.Exists(paths.ProvenanceFile)
            ? JsonSerializer.Deserialize<ProvenanceStore>(File.ReadAllText(paths.ProvenanceFile), JsonOpts) ?? new ProvenanceStore()
            : new ProvenanceStore();

    public void Save(ConfigPaths paths)
    {
        Directory.CreateDirectory(paths.Dir);
        File.WriteAllText(paths.ProvenanceFile, JsonSerializer.Serialize(this, JsonOpts));
    }

    public static void Clear(ConfigPaths paths)
    {
        if (File.Exists(paths.ProvenanceFile)) File.Delete(paths.ProvenanceFile);
    }

    /// <summary>Upsert by entry path. A rotation records the old fingerprint as retired and
    /// rewrites the origin — a freshly generated value is no longer exposed, which is
    /// exactly what makes rotation the way to empty the audit list.</summary>
    public ProvenanceRecord Upsert(string entryPath, string? uuid, string origin, string? fingerprintSha256, bool rotated = false)
    {
        var now = DateTimeOffset.UtcNow;
        var existing = Records.FirstOrDefault(r => r.Path == entryPath);
        if (existing is null)
        {
            var rec = new ProvenanceRecord { Path = entryPath, Uuid = uuid, Origin = origin, CreatedAtUtc = now, LastChangedUtc = now, FingerprintSha256 = fingerprintSha256 };
            Records.Add(rec);
            return rec;
        }
        if (rotated && existing.FingerprintSha256 is { Length: > 0 } old)
            existing.RetiredFingerprints.Add(old);
        existing.Uuid = uuid ?? existing.Uuid;
        existing.Origin = origin;
        existing.LastChangedUtc = now;
        if (fingerprintSha256 is not null) existing.FingerprintSha256 = fingerprintSha256;
        return existing;
    }

    public bool Remove(string entryPath) => Records.RemoveAll(r => r.Path == entryPath) > 0;

    public IReadOnlyList<ProvenanceRecord> Exposed => Records.Where(r => r.Origin == Origin.SeenByModel).ToList();
}
