using KeePassxcMcp.Infra;
using KeePassxcMcp.Tools;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

// Single executable, two modes. `mcp` is the agent-facing stdio server; `promote` is the
// human approver. They are separate processes on purpose: an MCP stdio server owns its
// stdin/stdout for JSON-RPC and can never prompt on a terminal — so approval lives here.

switch ((args.Length == 0 ? "mcp" : args[0]).ToLowerInvariant())
{
    case "mcp":
        return await RunMcpAsync();
    case "promote":
        return await RunPromoteAsync();
    case "status":
        return RunStatus();
    case "help" or "-h" or "--help":
        PrintUsage();
        return 0;
    default:
        Console.Error.WriteLine($"Unknown mode: {args[0]}");
        PrintUsage();
        return 2;
}

static async Task<int> RunMcpAsync()
{
    VaultConfig cfg;
    ConfigPaths paths;
    try
    {
        (cfg, paths) = ConfigLoader.Load();
    }
    catch (ConfigException ex)
    {
        // stdout belongs to JSON-RPC — config errors go to stderr, never stdout.
        await Console.Error.WriteLineAsync(ex.Message);
        return 2;
    }

    VaultContext.Init(cfg, paths);

    var builder = Host.CreateApplicationBuilder([]);
    builder.Logging.ClearProviders();
    builder.Logging.AddConsole(consoleLogOptions =>
    {
        // ALL logging to stderr: stdout must carry only JSON-RPC frames.
        consoleLogOptions.LogToStandardErrorThreshold = LogLevel.Trace;
    });
    builder.Services
        .AddMcpServer()
        .WithStdioServerTransport()
        .WithToolsFromAssembly();

    try
    {
        await builder.Build().RunAsync();
        return 0;
    }
    catch (Exception ex)
    {
        await Console.Error.WriteLineAsync("MCP server error: " + Redact.Apply(ex.Message, cfg.KnownSecrets));
        return 1;
    }
}

static async Task<int> RunPromoteAsync()
{
    VaultConfig cfg;
    ConfigPaths paths;
    try
    {
        (cfg, paths) = ConfigLoader.Load();
    }
    catch (ConfigException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 2;
    }

    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        Console.Error.WriteLine();
        Console.Error.WriteLine("Aborted (Ctrl+C). Staging and vault untouched.");
        Environment.Exit(130);
    };

    return await Promoter.RunAsync(cfg, paths, new KeePassCli(cfg.KeepassxcCliPath));
}

static int RunStatus()
{
    VaultConfig cfg;
    ConfigPaths paths;
    try
    {
        (cfg, paths) = ConfigLoader.Load();
    }
    catch (ConfigException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 2;
    }

    Console.WriteLine($"config        : {paths.ConfigFile}");
    Console.WriteLine($"main vault    : {cfg.MainVaultPath}" + (cfg.MainHasKeyfile ? " (password + keyfile)" : " (password only)"));
    Console.WriteLine($"staging vault : {cfg.StagingVaultPath}" + (File.Exists(cfg.StagingVaultPath) ? "" : " [not created yet]"));
    Console.WriteLine($"stagingPassword: [REDACTED — lives in config by design; see SECURITY.md]");
    Console.WriteLine($"keepassxc-cli : {cfg.KeepassxcCliPath}");

    var cli = new KeePassCli(cfg.KeepassxcCliPath);
    var staging = new StagingMaintenance(cli, cfg);
    try
    {
        var version = cli.VersionAsync().GetAwaiter().GetResult().StdOut.Trim();
        Console.WriteLine($"cli version   : {version}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"cli version   : unreachable ({Redact.Apply(ex.Message, cfg.KnownSecrets)})");
    }

    if (File.Exists(cfg.StagingVaultPath))
    {
        var entries = staging.ListEntryPathsAsync().GetAwaiter().GetResult();
        Console.WriteLine($"staged entries: {entries.Count}");
        foreach (var e in entries) Console.WriteLine($"  - {e}");
    }

    var pending = PendingRequest.TryLoad(paths);
    Console.WriteLine(pending is null
        ? "pending request : none"
        : $"pending request : {pending.Entries.Count} entries, {pending.Attachments.Count} attachments, requested {pending.RequestedAtUtc:O}");

    var state = PromoterState.Load(paths);
    Console.WriteLine(state.LastPromotedUtc is { } lp
        ? $"last promote    : {lp:O} ({state.LastPromotedEntryCount} entries)"
        : "last promote    : never");

    Console.WriteLine("main vault password: never in config, never on disk, never in this process — only the interactive `promote` mode reads it from you.");
    return 0;
}

static void PrintUsage()
{
    Console.Error.WriteLine("""
        keepassxc-mcp — MCP server + approver CLI for a KeePassXC vault (staging → human approval → merge)

        usage:
          keepassxc-mcp                stdio MCP server for the agent (tools: vault_stage_entry,
                                       vault_list_staged, vault_promote). NEVER touches the main vault
                                       password.
          keepassxc-mcp promote        HUMAN approver: review the staged request + live merge dry-run,
                                       confirm, type the master password. Run this in a real terminal.
          keepassxc-mcp status         show config (password redacted), staging contents, pending request.

        config: %APPDATA%\keepassxc-mcp\config.json on Windows, ~/.config/keepassxc-mcp/config.json on
        Linux/macOS, or set KEEPASSXC_MCP_CONFIG. Keep config and the kdbx files out of VCS/sync folders.
        """);
}
