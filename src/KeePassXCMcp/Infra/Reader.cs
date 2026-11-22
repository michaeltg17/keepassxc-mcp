using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeePassXCMcp.Infra;

// ---------------------------------------------------------------------------
// The reader session (SPEC.md E1). One master password typed once, in a terminal
// the MCP server can never read. The reader is a separate process (same identity-
// banner pattern as the approver): it holds the password in memory and services
// main-vault READ requests over a small file protocol — never pipes (the server
// must not own any channel through which the password could travel).
// Results are entry metadata only: `keepassxc-cli show` prints Password as
// PROTECTED, and the reader additionally redacts the master password from every
// result as belt-and-braces. Nothing that leaves the reader can carry a secret.
// ---------------------------------------------------------------------------

public sealed class ReaderSession
{
    public int Pid { get; set; }
    public DateTimeOffset OpenedAtUtc { get; set; }
    public int IdleMinutes { get; set; }
    /// <summary>Pid of the MCP server that opened this window (0 = human-launched, no
    /// orphan-watch). Not a secret; passed as an argv argument, never as data.</summary>
    public int ServerPid { get; set; }
}

public sealed class ReaderCommand
{
    public string Id { get; set; } = "";
    /// <summary>"search" | "get" | "close".</summary>
    public string Op { get; set; } = "";
    public string Arg { get; set; } = "";
}

public sealed class ReaderResult
{
    public string Id { get; set; } = "";
    public bool Ok { get; set; }
    public string Output { get; set; } = "";
    public string? Error { get; set; }
}

public static class ReaderProtocol
{
    public const int DefaultIdleMinutes = 10;

    internal static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Atomic write: temp file + move, so a poll never sees a half-written document.</summary>
    public static void WriteAtomic(string path, object value)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(value, JsonOpts));
        File.Move(tmp, path, overwrite: true);
    }

    public static T? TryReadAtomic<T>(string path) where T : class
    {
        try
        {
            return File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), JsonOpts) : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Session file present AND the recorded pid alive.</summary>
    public static bool TryGetLiveSession(ConfigPaths paths, out ReaderSession session)
    {
        session = ReaderProtocol.TryReadAtomic<ReaderSession>(paths.ReaderSessionFile) ?? new ReaderSession();
        if (session.Pid <= 0) return false;
        try
        {
            var proc = System.Diagnostics.Process.GetProcessById(session.Pid);
            return !proc.HasExited;
        }
        catch (ArgumentException)
        {
            return false; // pid no longer exists
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false; // process exists but is not accessible — treat as stale
        }
    }
}

/// <summary>The HUMAN side (`keepassxc-mcp reader`), run in a real terminal window.
/// Reads the master password interactively (masked, max 3 attempts — the ls-probe doubles
/// as the credential check), then services the file protocol until close/idle/orphan.</summary>
public static class ReaderRunner
{
    private const int MaxPasswordAttempts = 3;
    private const int PollMs = 200;

    public static async Task<int> RunAsync(VaultConfig cfg, ConfigPaths paths, KeePassCli cli,
        int serverPid = 0, int idleMinutes = ReaderProtocol.DefaultIdleMinutes, CancellationToken ct = default)
    {
        Console.Error.WriteLine("keepassxc-mcp reader — main-vault read session (reads only; nothing is ever written)");
        var self = Environment.ProcessPath ?? "";
        Console.Error.WriteLine($"this executable : {self} (v{AppInfo.Version})");
        if (self.Length > 0 && File.Exists(self))
        {
            var (selfSha, selfSize) = await Hashing.Sha256FileAsync(self, ct);
            Console.Error.WriteLine($"  its sha256    : {selfSha} ({selfSize} B) — verify before typing any password");
        }
        Console.Error.WriteLine();
        ApproverConsole.WaitEnter("Press Enter in this window to begin (nothing has been read yet): ");
        Console.Error.WriteLine($"main vault : {cfg.MainVaultPath}" + (cfg.MainHasKeyfile ? " (+ keyfile)" : " (password only)"));

        if (!File.Exists(cfg.MainVaultPath))
        {
            Console.Error.WriteLine($"Main vault not found at {cfg.MainVaultPath}. Nothing to read.");
            return 1;
        }

        var password = string.Empty;
        for (var attempt = 1; attempt <= MaxPasswordAttempts; attempt++)
        {
            var entered = ApproverConsole.ReadPassword($"Master password for the main vault (attempt {attempt}/{MaxPasswordAttempts}, input hidden): ");
            if (entered is null)
            {
                Console.Error.WriteLine("Input closed at the password prompt — exiting.");
                return 1;
            }
            if (entered.Length == 0)
            {
                Console.Error.WriteLine("Empty password — not tried against the vault.");
                continue;
            }
            var probe = await cli.UnlockProbeAsync(cfg.MainVaultPath, entered, cfg.MainKeyfilePath, ct);
            if (probe.Success)
            {
                password = entered;
                break;
            }
            Console.Error.WriteLine("Attempt failed: " + Redact.Apply(probe.FailureSummary, cfg.KnownSecrets));
        }
        if (password.Length == 0)
        {
            Console.Error.WriteLine($"{MaxPasswordAttempts} password attempts failed — no session opened.");
            return 1;
        }

        try
        {
            ReaderProtocol.WriteAtomic(paths.ReaderSessionFile, new ReaderSession
            {
                Pid = Environment.ProcessId,
                OpenedAtUtc = DateTimeOffset.UtcNow,
                IdleMinutes = idleMinutes,
                ServerPid = serverPid,
            });
            Console.Error.WriteLine($"Reader session open (idle timeout {idleMinutes} min" +
                (serverPid > 0 ? $", closes if server pid {serverPid} exits" : "") + "). Ctrl+C closes it.");

            var lastActivity = DateTimeOffset.UtcNow;
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(PollMs, ct);

                if (File.Exists(paths.ReaderCommandFile))
                {
                    lastActivity = DateTimeOffset.UtcNow;
                    var cmd = ReaderProtocol.TryReadAtomic<ReaderCommand>(paths.ReaderCommandFile);
                    File.Delete(paths.ReaderCommandFile);
                    if (cmd is null || string.IsNullOrEmpty(cmd.Id)) continue;

                    if (cmd.Op == "close")
                    {
                        ReaderProtocol.WriteAtomic(paths.ReaderResultFile, new ReaderResult { Id = cmd.Id, Ok = true, Output = "closed" });
                        Console.Error.WriteLine("Closed by request.");
                        return 0;
                    }

                    var result = await ServiceAsync(cfg, cli, password, cmd, ct);
                    ReaderProtocol.WriteAtomic(paths.ReaderResultFile, result);
                    continue;
                }

                if (DateTimeOffset.UtcNow - lastActivity > TimeSpan.FromMinutes(idleMinutes))
                {
                    Console.Error.WriteLine($"Idle for {idleMinutes} minutes — closing the reader session.");
                    return 0;
                }
                if (serverPid > 0 && !ProcessAlive(serverPid))
                {
                    Console.Error.WriteLine($"Server pid {serverPid} is gone — closing the reader session (orphan guard).");
                    return 0;
                }
            }
            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        finally
        {
            if (File.Exists(paths.ReaderSessionFile))
            {
                var owned = ReaderProtocol.TryReadAtomic<ReaderSession>(paths.ReaderSessionFile)?.Pid == Environment.ProcessId;
                if (owned) File.Delete(paths.ReaderSessionFile);
            }
            password = string.Empty;
        }
    }

    private static async Task<ReaderResult> ServiceAsync(VaultConfig cfg, KeePassCli cli, string password, ReaderCommand cmd, CancellationToken ct)
    {
        try
        {
            switch (cmd.Op)
            {
                case "search":
                {
                    var search = await cli.SearchAsync(cfg.MainVaultPath, password, cfg.MainKeyfilePath, cmd.Arg, ct);
                    var paths = search.StdOut
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Select(p => p.TrimStart('/'));
                    return Done(cmd, string.Join("\n", paths), password);
                }
                case "get":
                {
                    var show = await cli.ShowAsync(cfg.MainVaultPath, password, cfg.MainKeyfilePath, cmd.Arg, ct: ct);
                    return Done(cmd, show.StdOut, password);
                }
                default:
                    return new ReaderResult { Id = cmd.Id, Ok = false, Error = $"unknown op '{cmd.Op}'" };
            }
        }
        catch (KeePassCliException ex)
        {
            return new ReaderResult { Id = cmd.Id, Ok = false, Error = Redact.Apply(ex.Message, [password, .. cfg.KnownSecrets]) };
        }
    }

    private static ReaderResult Done(ReaderCommand cmd, string output, string password) => new()
    {
        Id = cmd.Id,
        Ok = true,
        // belt-and-braces: the master password is redacted from every result even though
        // no read path formats it into output in the first place (show masks Password).
        Output = Redact.Apply(output, [password]),
    };

    private static bool ProcessAlive(int pid)
    {
        try
        {
            return !System.Diagnostics.Process.GetProcessById(pid).HasExited;
        }
        catch (Exception e) when (e is ArgumentException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
}
