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
        PrintUsage(ConsoleUi.ForStderrDefaultTheme());
        return 0;
    default:
        var unknown = ConsoleUi.ForStderrDefaultTheme();
        unknown.Line($"Unknown mode: {args[0]}", Tone.Error);
        PrintUsage(unknown);
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
        ConsoleUi.ConfigError(ex.Message);
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
        var ui = ConsoleUi.ForStdoutDefaultTheme();
        ui.Line($"Approver window opened: {result.Detail}", Tone.Success);
        ui.Line("Review the manifest, confirm y, and type the master password in that window.", Tone.Faint);
        return 0;
    }
    ConsoleUi.ForStderrDefaultTheme().Line("Could not open an approver window: " + result.Detail, Tone.Error);
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
        ConsoleUi.ConfigError(ex.Message);
        return 2;
    }

    var serverPid = 0;
    if (Flag(args, "--server") is { } s)
    {
        if (!int.TryParse(s, out serverPid))
        {
            ConsoleUi.ForStderrDefaultTheme().Line("--server expects a numeric pid.", Tone.Error);
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
        var ui = ConsoleUi.ForStdoutDefaultTheme();
        ui.Line($"Reader window opened: {result.Detail}", Tone.Success);
        ui.Line("Type the master password once in that window; reads are served until it closes.", Tone.Faint);
        return 0;
    }
    ConsoleUi.ForStderrDefaultTheme().Line("Could not open a reader window: " + result.Detail, Tone.Error);
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
        ConsoleUi.ConfigError(ex.Message);
        return 2;
    }

    var label = Flag(args, "--label");
    if (string.IsNullOrWhiteSpace(label))
    {
        ConsoleUi.ForStderrDefaultTheme().Line("usage: keepassxc-mcp generate --label <group/entry> [--length N]", Tone.Error);
        return 2;
    }
    var length = 32;
    if (Flag(args, "--length") is { } l && !int.TryParse(l, out length))
    {
        ConsoleUi.ForStderrDefaultTheme().Line("--length expects a number.", Tone.Error);
        return 2;
    }

    try
    {
        var cli = new KeePassCli(cfg.KeepassxcCliPath);
        var receipt = await SecretOps.GenerateAsync(cfg, paths, cli, new StagingMaintenance(cli, cfg), label, new GenProfile(length));
        var ui = ConsoleUi.ForStdout(cfg);
        ui.Line("Generated (inside keepassxc-cli) and staged — value never printed anywhere. Provenance: generated.", Tone.Success);
        ui.Line(SecretOps.ToJson(receipt)); // the machine-readable receipt stays raw JSON, theme or not
        ui.Line("Promote to move it into the vault.", Tone.Faint);
        return 0;
    }
    catch (Exception ex) when (ex is ArgumentException or KeePassCliException or InvalidOperationException)
    {
        ConsoleUi.ForStderr(cfg).Line("Error: " + Redact.Apply(ex.Message, cfg.KnownSecrets), Tone.Error);
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
        ConsoleUi.ConfigError(ex.Message);
        return 2;
    }

    var label = Flag(args, "--label");
    if (string.IsNullOrWhiteSpace(label))
    {
        ConsoleUi.ForStderrDefaultTheme().Line("usage: echo <value> | keepassxc-mcp stage --label <group/entry> [--notes text]   (value is read from stdin, one line)", Tone.Error);
        return 2;
    }
    if (!Console.IsInputRedirected)
    {
        ConsoleUi.ForStderrDefaultTheme().Line("stdin is not a pipe — this verb takes the value on stdin so it never enters a conversation.", Tone.Error);
        return 2;
    }
    var value = Console.ReadLine();
    if (string.IsNullOrEmpty(value))
    {
        ConsoleUi.ForStderrDefaultTheme().Line("Empty stdin — nothing staged. Pipe exactly one line with the value.", Tone.Error);
        return 1;
    }

    try
    {
        var cli = new KeePassCli(cfg.KeepassxcCliPath);
        var receipt = await SecretOps.StageValueAsync(cfg, paths, cli, new StagingMaintenance(cli, cfg),
            label, new Secret(value.Trim()), Origin.Piped, Flag(args, "--notes"));
        var ui = ConsoleUi.ForStdout(cfg);
        ui.Line("Value piped stdin → staging (no agent saw it). Provenance: piped.", Tone.Success);
        ui.Line(SecretOps.ToJson(receipt)); // machine-readable receipt, raw
        ui.Line("Promote to move it into the vault.", Tone.Faint);
        return 0;
    }
    catch (Exception ex) when (ex is ArgumentException or KeePassCliException or InvalidOperationException)
    {
        ConsoleUi.ForStderr(cfg).Line("Error: " + Redact.Apply(ex.Message, cfg.KnownSecrets), Tone.Error);
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
        ConsoleUi.ConfigError(ex.Message);
        return 2;
    }

    var store = ProvenanceStore.Load(paths);
    var ui = ConsoleUi.ForStdout(cfg);
    using (ui.Section("Exposure audit"))
    {
        ui.Line($"tracked secrets: {store.Records.Count} (exposed to a model: {store.Exposed.Count})",
            store.Exposed.Count > 0 ? Tone.Warning : Tone.Success);
        if (ui.Rich)
        {
            // recent-requests style table; seen-by-model rows are the ones to act on.
            ui.Table(
                ["entry path", "origin", "changed", "remedy"],
                store.Records.Select(r => new[] { r.Path, r.Origin.ToString(), r.LastChangedUtc.ToString("O"), r.Origin == Origin.SeenByModel ? "rotate or dismiss" : "" }).ToList(),
                store.Records.Select(r => r.Origin == Origin.SeenByModel ? Tone.Accent : Tone.Muted).ToList());
        }
        else
        {
            foreach (var r in store.Records)
                ui.Line($"  {r.Path}: {r.Origin} (changed {r.LastChangedUtc:O})" + (r.Origin == Origin.SeenByModel ? "  <-- rotate or dismiss" : ""));
        }
        if (store.Exposed.Count > 0)
            ui.Line("Rotate the seen-by-model entries (vault_rotate before promote, or at the service), or delete this file to start fresh — it never contains secret values.", Tone.Faint);
    }
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
        ConsoleUi.ConfigError(ex.Message);
        return 2;
    }

    // Same content in the same order always; on a real terminal it arrives as themed
    // sections (opencode hairline sections / strata titled cards) over the same rows.
    var ui = ConsoleUi.ForStdout(cfg);
    var cli = new KeePassCli(cfg.KeepassxcCliPath);
    var staging = new StagingMaintenance(cli, cfg);

    using (ui.Section("Setup"))
    {
        ui.Kv("config", paths.ConfigFile, 14);
        ui.Kv("app version", AppInfo.Version, 14);
        ui.Kv("main vault", cfg.MainVaultPath + (cfg.MainHasKeyfile ? " (password + keyfile)" : " (password only)"), 14);
        ui.Kv("staging vault", cfg.StagingVaultPath + (File.Exists(cfg.StagingVaultPath) ? "" : " [not created yet]"), 14);
        ui.Kv("stagingPassword", "[REDACTED — lives in config by design; see SECURITY.md]", 14, Tone.Warning);
        ui.Kv("keepassxc-cli", cfg.KeepassxcCliPath, 14);

        try
        {
            var version = cli.VersionAsync().GetAwaiter().GetResult().StdOut.Trim();
            ui.Kv("cli version", version, 14);
        }
        catch (Exception ex)
        {
            ui.Kv("cli version", $"unreachable ({Redact.Apply(ex.Message, cfg.KnownSecrets)})", 14, Tone.Error);
        }
    }

    using (ui.Section("Staging"))
    {
        if (File.Exists(cfg.StagingVaultPath))
        {
            var entries = staging.ListEntryPathsAsync().GetAwaiter().GetResult();
            ui.Kv("staged entries", entries.Count.ToString(), 14, entries.Count > 0 ? Tone.Accent : Tone.Muted);
            foreach (var e in entries) ui.Item(e);
        }
    }

    using (ui.Section("Sessions"))
    {
        var pending = PendingRequest.TryLoad(paths);
        ui.Kv("pending request", pending is null
                ? "none"
                : $"{pending.Entries.Count} entries, {pending.Attachments.Count} attachments, requested {pending.RequestedAtUtc:O}", 16,
            pending is null ? Tone.Muted : Tone.Accent);

        if (ReaderProtocol.TryGetLiveSession(paths, out var reader))
            ui.Kv("reader session", $"OPEN (pid {reader.Pid} since {reader.OpenedAtUtc:O}, idle {reader.IdleMinutes} min) — reads only", 16, Tone.Success);
        else
            ui.Kv("reader session", "none (start with `keepassxc-mcp reader` — a main-vault READ session)", 16, Tone.Muted);
    }

    var provenance = ProvenanceStore.Load(paths);
    using (ui.Section("Exposure"))
    {
        ui.Kv("provenance", $"{provenance.Records.Count} tracked, {provenance.Exposed.Count} seen-by-model" +
            (provenance.Exposed.Count > 0 ? " (rotate or dismiss — see `keepassxc-mcp audit`)" : ""), 16,
            provenance.Exposed.Count > 0 ? Tone.Warning : Tone.Text);
    }

    using (ui.Section("Flow"))
    {
        var state = PromoterState.Load(paths);
        ui.Kv("last promote", state.LastPromotedUtc is { } lp
                ? $"{lp:O} ({state.LastPromotedEntryCount} entries)"
                : "never", 16);
        ui.Kv("approver window", cfg.AllowApproverWindow
            ? "agent-openable (vault_open_approver / promote-window; disable with \"allowAgentApproverWindow\": false)"
            : "human-only (allowAgentApproverWindow: false)", 16);
    }

    ui.Line("main vault password: never in config, never on disk, never in this process — only the interactive `promote` mode reads it from you.", Tone.Faint);
    return 0;
}

static void PrintUsage(ConsoleUi ui)
{
    // The usage text never changes — on a terminal the mode names and section labels
    // are painted; piped output is the same block byte for byte.
    var block = """
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
        """;

    foreach (var line in block.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n'))
    {
        if (!ui.Rich)
        {
            ui.Line(line);
            continue;
        }
        var cmd = System.Text.RegularExpressions.Regex.Match(line, @"^(?<lead>\s*keepassxc-mcp(?:\s+\S+)?)(?<desc>\s.*)$");
        if (line.StartsWith("keepassxc-mcp") || line.TrimStart() == "usage:")
            ui.Line(line, Tone.AccentStructural);
        else if (cmd.Success)
            ui.Segments((cmd.Groups["lead"].Value, Tone.Accent), (cmd.Groups["desc"].Value, Tone.Text));
        else if (line.TrimStart().StartsWith("config:"))
            ui.Segments(("config:", Tone.AccentStructural), (line.TrimStart()["config:".Length..], Tone.Muted));
        else
            ui.Line(line, Tone.Muted); // descriptions, continuation lines, blanks
    }
}
