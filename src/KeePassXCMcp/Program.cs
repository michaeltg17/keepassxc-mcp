using KeePassXCMcp.Infra;
using KeePassXCMcp.Tools;
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
    case "promote-window":
        return RunPromoteWindow();
    case "reader":
        return await RunReaderAsync(args);
    case "reader-window":
        return RunReaderWindow();
    case "generate":
        return await RunGenerateAsync(args);
    case "stage":
        return await RunStageVerbAsync(args);
    case "audit":
        return RunAuditVerb();
    case "status":
        return RunStatus();
    case "version" or "--version" or "-v":
        Console.WriteLine($"keepassxc-mcp {AppInfo.Version}");
        return 0;
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
        Environment.Exit((int)Promoter.Exit.Cancelled);
    };

    return (int)await Promoter.RunAsync(cfg, paths, new KeePassCli(cfg.KeepassxcCliPath));
}

static int RunPromoteWindow()
{
    var result = ApproverLauncher.TryOpenPromoteWindow();
    if (result.Launched)
    {
        Console.WriteLine($"Approver window opened: {result.Detail}");
        Console.WriteLine("Review the manifest, confirm y, and type the master password in that window.");
        return 0;
    }
    Console.Error.WriteLine("Could not open an approver window: " + result.Detail);
    return 1;
}

/// <summary>Human-run reader mode: types the master password once, then services main-vault
/// reads over the file protocol (SPEC.md E1). `--server <pid>` from vault_reader_open
/// enables the orphan guard; human-launched sessions have none (they idle out instead).</summary>
static async Task<int> RunReaderAsync(string[] args)
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

    var serverPid = 0;
    if (Flag(args, "--server") is { } s)
    {
        if (!int.TryParse(s, out serverPid))
        {
            Console.Error.WriteLine("--server expects a numeric pid.");
            return 2;
        }
    }

    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        Console.Error.WriteLine();
        Console.Error.WriteLine("Closed (Ctrl+C). Nothing was ever read or written.");
        Environment.Exit(0);
    };

    return await ReaderRunner.RunAsync(cfg, paths, new KeePassCli(cfg.KeepassxcCliPath), serverPid);
}

static int RunReaderWindow()
{
    var result = ApproverLauncher.TryOpenReaderWindow(serverPid: 0); // CLI-launched: no orphan watch, idles out
    if (result.Launched)
    {
        Console.WriteLine($"Reader window opened: {result.Detail}");
        Console.WriteLine("Type the master password once in that window; reads are served until it closes.");
        return 0;
    }
    Console.Error.WriteLine("Could not open a reader window: " + result.Detail);
    return 1;
}

/// <summary>Human/agent CLI front door for F1 (same operation as vault_generate).</summary>
static async Task<int> RunGenerateAsync(string[] args)
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

    var label = Flag(args, "--label");
    if (string.IsNullOrWhiteSpace(label))
    {
        Console.Error.WriteLine("usage: keepassxc-mcp generate --label <group/entry> [--length N]");
        return 2;
    }
    var length = 32;
    if (Flag(args, "--length") is { } l && !int.TryParse(l, out length))
    {
        Console.Error.WriteLine("--length expects a number.");
        return 2;
    }

    try
    {
        var cli = new KeePassCli(cfg.KeepassxcCliPath);
        var receipt = await SecretOps.GenerateAsync(cfg, paths, cli, new StagingMaintenance(cli, cfg), label, new GenProfile(length));
        Console.WriteLine($"Generated (inside keepassxc-cli) and staged — value never printed anywhere. Provenance: generated.");
        Console.WriteLine(SecretOps.ToJson(receipt));
        Console.WriteLine("Promote to move it into the vault.");
        return 0;
    }
    catch (Exception ex) when (ex is ArgumentException or KeePassCliException or InvalidOperationException)
    {
        Console.Error.WriteLine("Error: " + Redact.Apply(ex.Message, cfg.KnownSecrets));
        return 1;
    }
}

/// <summary>F2.1: pipe a service-generated value straight into staging WITHOUT any agent
/// seeing it: `gh api … | keepassxc-mcp stage --label Services/github-token`. The value
/// flows stdin → keepassxc-cli stdin; provenance is recorded as 'piped'.</summary>
static async Task<int> RunStageVerbAsync(string[] args)
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

    var label = Flag(args, "--label");
    if (string.IsNullOrWhiteSpace(label))
    {
        Console.Error.WriteLine("usage: echo <value> | keepassxc-mcp stage --label <group/entry> [--notes text]   (value is read from stdin, one line)");
        return 2;
    }
    if (!Console.IsInputRedirected)
    {
        Console.Error.WriteLine("stdin is not a pipe — this verb takes the value on stdin so it never enters a conversation.");
        return 2;
    }
    var value = Console.ReadLine();
    if (string.IsNullOrEmpty(value))
    {
        Console.Error.WriteLine("Empty stdin — nothing staged. Pipe exactly one line with the value.");
        return 1;
    }

    try
    {
        var cli = new KeePassCli(cfg.KeepassxcCliPath);
        var receipt = await SecretOps.StageValueAsync(cfg, paths, cli, new StagingMaintenance(cli, cfg),
            label, new Secret(value.Trim()), Origin.Piped, Flag(args, "--notes"));
        Console.WriteLine("Value piped stdin → staging (no agent saw it). Provenance: piped.");
        Console.WriteLine(SecretOps.ToJson(receipt));
        Console.WriteLine("Promote to move it into the vault.");
        return 0;
    }
    catch (Exception ex) when (ex is ArgumentException or KeePassCliException or InvalidOperationException)
    {
        Console.Error.WriteLine("Error: " + Redact.Apply(ex.Message, cfg.KnownSecrets));
        return 1;
    }
}

static int RunAuditVerb()
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

    var store = ProvenanceStore.Load(paths);
    Console.WriteLine($"tracked secrets: {store.Records.Count} (exposed to a model: {store.Exposed.Count})");
    foreach (var r in store.Records)
        Console.WriteLine($"  {r.Path}: {r.Origin} (changed {r.LastChangedUtc:O})" + (r.Origin == Origin.SeenByModel ? "  <-- rotate or dismiss" : ""));
    if (store.Exposed.Count > 0)
        Console.WriteLine("Rotate the seen-by-model entries (vault_rotate before promote, or at the service), or delete this file to start fresh — it never contains secret values.");
    return 0;
}

static string? Flag(string[] args, string name)
{
    for (var i = 0; i < args.Length - 1; i++)
        if (args[i] == name) return args[i + 1];
    return null;
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
    Console.WriteLine($"app version   : {AppInfo.Version}");
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

    if (ReaderProtocol.TryGetLiveSession(paths, out var reader))
        Console.WriteLine($"reader session  : OPEN (pid {reader.Pid} since {reader.OpenedAtUtc:O}, idle {reader.IdleMinutes} min) — reads only");
    else
        Console.WriteLine("reader session  : none (start with `keepassxc-mcp reader` — a main-vault READ session)");

    var provenance = ProvenanceStore.Load(paths);
    Console.WriteLine($"provenance      : {provenance.Records.Count} tracked, {provenance.Exposed.Count} seen-by-model" +
        (provenance.Exposed.Count > 0 ? " (rotate or dismiss — see `keepassxc-mcp audit`)" : ""));

    var state = PromoterState.Load(paths);
    Console.WriteLine(state.LastPromotedUtc is { } lp
        ? $"last promote    : {lp:O} ({state.LastPromotedEntryCount} entries)"
        : "last promote    : never");
    Console.WriteLine($"approver window : {(cfg.AllowApproverWindow
        ? "agent-openable (vault_open_approver / promote-window; disable with \"allowAgentApproverWindow\": false)"
        : "human-only (allowAgentApproverWindow: false)")}");

    Console.WriteLine("main vault password: never in config, never on disk, never in this process — only the interactive `promote` mode reads it from you.");
    return 0;
}

static void PrintUsage()
{
    Console.Error.WriteLine("""
        keepassxc-mcp — MCP server + approver/reader CLI for a KeePassXC vault
                      (writes: staging → human approval → merge; reads: human-opened read session)

        usage:
          keepassxc-mcp                stdio MCP server for the agent. Tools: vault_stage_entry,
                                       vault_list_staged, vault_promote, vault_open_approver,
                                       vault_reader_open/close, vault_search, vault_get,
                                       vault_generate, vault_stage_value, vault_rotate,
                                       vault_audit, vault_audit_dismiss (see SPEC.md for the flows).
                                       NEVER touches the main vault password.
          keepassxc-mcp promote        HUMAN approver: review the staged request + live merge dry-run,
                                       confirm, type the master password. Run this in a real terminal.
          keepassxc-mcp promote-window opens `promote` in a new visible terminal window (the launcher
                                       passes no data; a human still types y + the password there).
          keepassxc-mcp reader         HUMAN read session: type the master password ONCE; serves
                                       main-vault reads (paths + metadata, never values) until
                                       close/idle. Writes never happen here.
          keepassxc-mcp reader-window  opens `reader` in a new visible terminal window.
          keepassxc-mcp generate       generate a NEW secret inside keepassxc-cli and stage it
                                       (--label <path> [--length N]; the value is never printed).
          keepassxc-mcp stage          pipe a service-generated value into staging WITHOUT any agent
                                       seeing it: echo <value> | keepassxc-mcp stage --label <path>
          keepassxc-mcp audit          list tracked secrets + which were ever visible to a model.
          keepassxc-mcp status         show config (password redacted), staging contents, pending
                                       request, reader session, provenance summary.
          keepassxc-mcp version        print the build version (also: --version).

        config: %APPDATA%\keepassxc-mcp\config.json on Windows, ~/.config/keepassxc-mcp/config.json on
        Linux/macOS, or set KEEPASSXC_MCP_CONFIG. Keep config and the kdbx files out of VCS/sync folders.
        """);
}
