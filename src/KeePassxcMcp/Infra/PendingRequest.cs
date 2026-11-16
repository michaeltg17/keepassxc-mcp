using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeePassxcMcp.Infra;

public sealed record StagedAttachmentInfo(string EntryPath, string Name, long SizeBytes, string Sha256);

public sealed record StagedEntryInfo(string Path, string Group, string Title, string Notes);

/// <summary>
/// The agent's promotion REQUEST — a snapshot of staging (entries + attachment
/// name/size/sha256) written by vault_promote. It records intent only: it is NOT a diff
/// against the main vault, because only the approver (who can unlock the main vault)
/// can produce the real merge diff, and it is computed live at approval time.
/// </summary>
public sealed class PendingRequest
{
    public int Version { get; set; } = 1;
    public DateTimeOffset RequestedAtUtc { get; set; }
    public string MainVaultPath { get; set; } = "";
    public List<StagedEntryInfo> Entries { get; set; } = [];
    public List<StagedAttachmentInfo> Attachments { get; set; } = [];

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static PendingRequest? TryLoad(ConfigPaths paths)
    {
        if (!File.Exists(paths.PendingFile)) return null;
        try
        {
            return JsonSerializer.Deserialize<PendingRequest>(File.ReadAllText(paths.PendingFile), JsonOpts);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static void Save(ConfigPaths paths, PendingRequest request)
    {
        Directory.CreateDirectory(paths.Dir);
        File.WriteAllText(paths.PendingFile, JsonSerializer.Serialize(request, JsonOpts));
    }

    public static void Clear(ConfigPaths paths)
    {
        if (File.Exists(paths.PendingFile)) File.Delete(paths.PendingFile);
    }
}

/// <summary>Promoter bookkeeping: main-vault mtime at last promote + last promote time.</summary>
public sealed class PromoterState
{
    public DateTimeOffset? LastPromotedUtc { get; set; }
    public DateTimeOffset? LastMainMtimeUtc { get; set; }
    public int LastPromotedEntryCount { get; set; }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static PromoterState Load(ConfigPaths paths) =>
        File.Exists(paths.StateFile)
            ? JsonSerializer.Deserialize<PromoterState>(File.ReadAllText(paths.StateFile), JsonOpts) ?? new PromoterState()
            : new PromoterState();

    public void Save(ConfigPaths paths)
    {
        Directory.CreateDirectory(paths.Dir);
        File.WriteAllText(paths.StateFile, JsonSerializer.Serialize(this, JsonOpts));
    }
}
