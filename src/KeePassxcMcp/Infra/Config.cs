using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeePassxcMcp.Infra;

/// <summary>The whole configuration. Tool-facing vault paths come from here ONLY —
/// MCP tools can never target arbitrary databases.</summary>
public sealed record VaultConfig(
    string MainVaultPath,
    string? MainKeyfilePath,
    string StagingVaultPath,
    string StagingPassword,
    string KeepassxcCliPath)
{
    /// <summary>Main vault may be password-only (null keyfile) or password+keyfile.</summary>
    public bool MainHasKeyfile => !string.IsNullOrWhiteSpace(MainKeyfilePath);

    /// <summary>Secrets this config holds, for the redaction filter. The main vault
    /// password is deliberately NOT part of this record — it never exists in config.</summary>
    public string[] KnownSecrets => [StagingPassword];
}

/// <summary>Where config.json (and the files that live beside it) are found per-OS.</summary>
public sealed record ConfigPaths(string Dir, string ConfigFile)
{
    public string PendingFile => Path.Combine(Dir, "pending-request.json");
    public string StateFile => Path.Combine(Dir, "state.json");

    public static ConfigPaths Resolve()
    {
        var fromEnv = Environment.GetEnvironmentVariable("KEEPASSXC_MCP_CONFIG");
        if (!string.IsNullOrWhiteSpace(fromEnv))
        {
            // Either a directory containing config.json, or an explicit config.json path.
            if (Path.GetFileName(fromEnv).EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                return new ConfigPaths(Path.GetDirectoryName(Path.GetFullPath(fromEnv))!, Path.GetFullPath(fromEnv));
            return new ConfigPaths(Path.GetFullPath(fromEnv), Path.Combine(fromEnv, "config.json"));
        }

        string dir;
        if (OperatingSystem.IsWindows())
            dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "keepassxc-mcp");
        else
        {
            var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            dir = Path.Combine(string.IsNullOrWhiteSpace(xdg) ? Path.Combine(home, ".config") : xdg, "keepassxc-mcp");
        }
        return new ConfigPaths(dir, Path.Combine(dir, "config.json"));
    }
}

public static class ConfigLoader
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>Throws ConfigException with an actionable message on any problem.</summary>
    public static (VaultConfig Config, ConfigPaths Paths) Load()
    {
        var paths = ConfigPaths.Resolve();
        if (!File.Exists(paths.ConfigFile))
            throw new ConfigException(
                $"No config found at {paths.ConfigFile}. Create it with keys: " +
                "mainVaultPath, mainKeyfilePath (optional), stagingVaultPath, stagingPassword, keepassxcCliPath (optional, default 'keepassxc-cli').");

        VaultConfig? cfg;
        try
        {
            cfg = JsonSerializer.Deserialize<VaultConfig>(File.ReadAllText(paths.ConfigFile), JsonOpts);
        }
        catch (JsonException ex)
        {
            throw new ConfigException($"Could not parse {paths.ConfigFile}: {ex.Message}");
        }

        if (cfg is null)
            throw new ConfigException($"Config at {paths.ConfigFile} is empty.");

        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(cfg.MainVaultPath)) errors.Add("mainVaultPath is required.");
        if (string.IsNullOrWhiteSpace(cfg.StagingVaultPath)) errors.Add("stagingVaultPath is required.");
        if (string.IsNullOrEmpty(cfg.StagingPassword))
            errors.Add("stagingPassword is required (kdbx format-mandatory; it is not a security boundary).");
        if (string.IsNullOrWhiteSpace(cfg.KeepassxcCliPath))
            cfg = cfg with { KeepassxcCliPath = "keepassxc-cli" };
        if (errors.Count > 0)
            throw new ConfigException(string.Join(' ', errors));

        return (cfg, paths);
    }
}

public sealed class ConfigException(string message) : Exception(message);
