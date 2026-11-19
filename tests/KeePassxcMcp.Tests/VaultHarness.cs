using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KeePassxcMcp.Infra;

namespace KeePassxcMcp.Tests;

/// <summary>Throwaway main+staging kdbx pair in a temp dir with a fake config — the plan's
/// integration harness. Cover both main variants: password-only and password+keyfile.</summary>
public sealed class VaultHarness : IDisposable
{
    public const string MainPassword = "test-main-pw-123";
    public const string StagingPassword = "test-staging-pw-123";

    public string Dir { get; }
    public string MainPath { get; }
    public string StagingPath { get; }
    public string KeyfilePath { get; }
    public ConfigPaths Paths { get; }
    public VaultConfig Config { get; }
    public KeePassCli Cli { get; }
    public StagingMaintenance Staging { get; }
    public string AttachmentsSourceDir { get; }

    public static async Task<VaultHarness> CreateAsync(bool mainWithKeyfile = false)
    {
        var dir = Path.Combine(Path.GetTempPath(), "kpxc-mcp-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var harness = new VaultHarness(dir, mainWithKeyfile);
        await harness.Cli.DbCreateAsync(harness.MainPath, MainPassword, harness.MainHasKeyfile ? harness.KeyfilePath : null);
        await harness.Cli.DbCreateAsync(harness.StagingPath, StagingPassword);
        harness.WriteConfigFile();
        return harness;
    }

    private VaultHarness(string dir, bool mainHasKeyfile)
    {
        Dir = dir;
        MainHasKeyfile = mainHasKeyfile;
        MainPath = Path.Combine(dir, "main.kdbx");
        StagingPath = Path.Combine(dir, "staging.kdbx");
        KeyfilePath = Path.Combine(dir, "main.key");
        AttachmentsSourceDir = Path.Combine(dir, "files");
        Directory.CreateDirectory(AttachmentsSourceDir);
        Paths = new ConfigPaths(dir, Path.Combine(dir, "config.json"));
        Cli = new KeePassCli(CliProbe.Path);
        Staging = new StagingMaintenance(Cli, ConfigPlaceholder);
        Config = ConfigPlaceholder;
        if (MainHasKeyfile) File.WriteAllText(KeyfilePath, GenerateXmlKeyfileContents());
    }

    public bool MainHasKeyfile { get; }

    private VaultConfig ConfigPlaceholder => new(
        MainVaultPath: MainPath,
        MainKeyfilePath: MainHasKeyfile ? KeyfilePath : null,
        StagingVaultPath: StagingPath,
        StagingPassword: StagingPassword,
        KeepassxcCliPath: CliProbe.Path);

    public void WriteConfigFile() => WriteConfigFile(Config);

    public void WriteConfigFile(VaultConfig cfg) =>
        File.WriteAllText(Paths.ConfigFile, JsonSerializer.Serialize(cfg,
            new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));

    /// <summary>Creates a temp attachment file with random-ish content and returns its path.</summary>
    public string CreateAttachmentFile(string name, int size = 1024)
    {
        var bytes = RandomNumberGenerator.GetBytes(size);
        var path = Path.Combine(AttachmentsSourceDir, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    public async Task<(string EntryPath, List<(string Name, string Sha256, long Size)> Attachments)> StageAsync(string group, string title, string notes, params string[] attachmentSourcePaths)
    {
        var receipt = await KeePassxcMcp.Tools.StagingOps.StageEntryAsync(Config, Cli, Staging, group, title, notes, attachmentSourcePaths);
        return (receipt.Entry, receipt.Attachments.Select(a => (a.Name, a.Sha256, a.Bytes)).ToList());
    }

    /// <summary>Records a PendingRequest from current staging (what vault_promote does).</summary>
    public async Task<PendingRequest> RecordPromotionRequestAsync()
    {
        var snapshot = await KeePassxcMcp.Tools.StagingOps.SnapshotStagingAsync(Config, Cli, Staging);
        var request = new PendingRequest
        {
            RequestedAtUtc = snapshot.SnapshotAtUtc,
            MainVaultPath = Config.MainVaultPath,
            Entries = snapshot.Entries.Select(e => new StagedEntryInfo(e.Path, e.Group, e.Title, e.Notes)).ToList(),
            Attachments = snapshot.Entries.SelectMany(e => e.Attachments).ToList(),
        };
        PendingRequest.Save(Paths, request);
        return request;
    }

    // ---- main-vault assertions (always via keepassxc-cli with the main password) ----

    public async Task<string> ShowMainAsync(string entryPath) =>
        (await Cli.ShowAsync(MainPath, MainPassword, MainHasKeyfile ? KeyfilePath : null, entryPath)).StdOut;

    public async Task<bool> MainHasEntryAsync(string entryPath) =>
        (await Cli.ShowRawAsync(MainPath, MainPassword, MainHasKeyfile ? KeyfilePath : null, entryPath)).Success;

    public async Task<IReadOnlyList<string>> StagedEntryPathsAsync() => await Staging.ListEntryPathsAsync();

    public static string ServerExePath => Path.Combine(
        AppContext.BaseDirectory, "serverapp",
        OperatingSystem.IsWindows() ? "keepassxc-mcp.exe" : "keepassxc-mcp");

    private static string GenerateXmlKeyfileContents()
    {
        var b64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <KeyFile>
                <Key>
                    <Version>2.0</Version>
                    <Data>
                        {b64}
                    </Data>
                </Key>
            </KeyFile>
            """;
    }

    public void Dispose()
    {
        try { Directory.Delete(Dir, recursive: true); } catch (IOException) { }
    }
}
