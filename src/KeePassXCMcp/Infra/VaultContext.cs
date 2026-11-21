using KeePassXCMcp.Infra;

namespace KeePassXCMcp.Tools;

/// <summary>Startup-initialized context for the tool classes: config paths are fixed at
/// launch, so MCP tools can NEVER target arbitrary databases — only what config.json says.</summary>
public static class VaultContext
{
    public static VaultConfig Config { get; private set; } = null!;
    public static ConfigPaths Paths { get; private set; } = null!;
    public static KeePassCli Cli { get; private set; } = null!;
    public static StagingMaintenance Staging { get; private set; } = null!;
    public static bool Initialized => Cli is not null;

    public static void Init(VaultConfig cfg, ConfigPaths paths)
    {
        Config = cfg;
        Paths = paths;
        Cli = new KeePassCli(cfg.KeepassxcCliPath);
        Staging = new StagingMaintenance(Cli, cfg);
    }
}
