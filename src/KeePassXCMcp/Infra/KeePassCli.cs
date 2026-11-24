using System.Diagnostics;
using System.Text;

namespace KeePassXCMcp.Infra;

public sealed record CliResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Success => ExitCode == 0;

    /// <summary>Short failure description safe for users/logs (never contains stdin).</summary>
    public string FailureSummary =>
        $"keepassxc-cli exited {ExitCode}: {Shorten(StdErr.Trim().Length > 0 ? StdErr.Trim() : StdOut.Trim())}";

    private static string Shorten(string s) => s.Length <= 400 ? s : s[..400] + "…";
}

public sealed class KeePassCliException(string message) : Exception(message);

/// <summary>Password generation profile passed to keepassxc-cli's own generator
/// (`add -g` / `edit -g`). The generator lives in the official binary — this repo
/// holds no password-generation code (the `-L` length maps to keepassxc-cli's range).</summary>
public sealed record GenProfile(int Length = 32)
{
    public bool Lower { get; init; } = true;
    public bool Upper { get; init; } = true;
    public bool Numeric { get; init; } = true;
    public bool Special { get; init; } = true;
    public bool EveryGroup { get; init; } = true;

    public List<string> ArgFlags()
    {
        if (Length is < 6 or > 128)
            throw new ArgumentException("length must be between 6 and 128.");
        var flags = new List<string> { "-L", Length.ToString() };
        if (Lower) flags.Add("-l");
        if (Upper) flags.Add("-U");
        if (Numeric) flags.Add("-n");
        if (Special) flags.Add("-s");
        if (!(Lower || Upper || Numeric || Special))
            throw new ArgumentException("at least one character class must be enabled.");
        if (EveryGroup && Lower && Upper && Numeric && Special) flags.Add("--every-group");
        return flags;
    }
}

/// <summary>
/// Process runner for the official keepassxc-cli. All invocation is via argv arrays —
/// never shell strings — and unlock passwords are fed ONLY through stdin, never argv.
/// This repo implements no kdbx crypto; every vault operation is keepassxc-cli's.
/// </summary>
public sealed class KeePassCli(string exePath)
{
    public string ExePath { get; } = exePath;

    public async Task<CliResult> RunAsync(
        IReadOnlyList<string> args,
        IReadOnlyList<string>? stdinLines = null,
        CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = ExePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdinLines is not null,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
        };
        if (stdinLines is not null) psi.StandardInputEncoding = new UTF8Encoding(false);
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var proc = new Process { StartInfo = psi };
        if (!proc.Start())
            throw new KeePassCliException($"Could not start '{ExePath}'. Is KeePassXC installed? (config key: keepassxcCliPath)");

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);
        if (stdinLines is not null)
        {
            foreach (var line in stdinLines)
                proc.StandardInput.WriteLine(line);
            await proc.StandardInput.FlushAsync(ct);
            proc.StandardInput.Close();
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        await proc.WaitForExitAsync(ct);
        return new CliResult(proc.ExitCode, stdout, stderr);
    }

    public async Task<CliResult> RunCheckedAsync(
        IReadOnlyList<string> args,
        IReadOnlyList<string>? stdinLines = null,
        CancellationToken ct = default)
    {
        var result = await RunAsync(args, stdinLines, ct);
        if (!result.Success)
            throw new KeePassCliException(result.FailureSummary);
        return result;
    }

    // ---- typed wrappers ----------------------------------------------------

    /// <summary>Read-only unlock probe: `ls -q -f` succeeds only with a valid key.
    /// Used by the reader mode to validate the typed master password before going idle.</summary>
    public Task<CliResult> UnlockProbeAsync(string dbPath, string password, string? keyfilePath, CancellationToken ct = default)
        => RunAsync(WithKeyfile(["ls", "-q", "-f"], keyfilePath).Concat([dbPath]).ToList(), [password], ct);

    /// <summary>`db-create -p <db>` (+ optional keyfile). kdbx cannot have empty password
    /// AND empty keyfile, so the password is format-mandatory. Prompts twice: pw, repeat.</summary>
    public Task<CliResult> DbCreateAsync(string dbPath, string password, string? keyfilePath = null, CancellationToken ct = default)
    {
        var args = new List<string> { "db-create", "-p" };
        if (keyfilePath is not null) { args.Add("--set-key-file"); args.Add(keyfilePath); }
        args.Add(dbPath);
        return RunCheckedAsync(args, [password, password], ct);
    }

    /// <summary>`mkdir` walks one level at a time (keepassxc-cli has no -p): creates each
    /// missing segment of a group path. "already exists" is tolerated.</summary>
    public async Task EnsureGroupAsync(string dbPath, string password, string? keyfilePath, string group, CancellationToken ct = default)
    {
        var segments = group.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var current = new StringBuilder();
        for (var i = 0; i < segments.Length; i++)
        {
            if (current.Length > 0) current.Append('/');
            current.Append(segments[i]);
            var path = current.ToString();
            var result = await RunAsync(
                WithKeyfile(["mkdir", "-q"], keyfilePath).Concat([dbPath, path]).ToList(),
                [password], ct);
            if (!result.Success && !result.StdErr.Contains("already exists", StringComparison.OrdinalIgnoreCase))
                throw new KeePassCliException($"mkdir {path}: {result.FailureSummary}");
        }
    }

    public Task<CliResult> AddEntryAsync(string dbPath, string password, string? keyfilePath, string entryPath, string notes, CancellationToken ct = default)
        => RunAsync(WithKeyfile(["add", "-q"], keyfilePath).Concat([dbPath, entryPath, "--notes", notes]).ToList(), [password], ct);

    /// <summary>`rm -q` — moves an entry to the database's Recycle Bin (KeePass semantics;
    /// rm on an entry already IN the bin deletes it for good). Password via stdin.</summary>
    public Task<CliResult> RemoveEntryAsync(string dbPath, string password, string? keyfilePath, string entryPath, CancellationToken ct = default)
        => RunAsync(WithKeyfile(["rm", "-q"], keyfilePath).Concat([dbPath, entryPath]).ToList(), [password], ct);

    public Task<CliResult> EditNotesAsync(string dbPath, string password, string? keyfilePath, string entryPath, string notes, CancellationToken ct = default)
        => RunCheckedAsync(WithKeyfile(["edit", "-q"], keyfilePath).Concat([dbPath, entryPath, "--notes", notes]).ToList(), [password], ct);

    public Task<CliResult> ImportAttachmentAsync(string dbPath, string password, string? keyfilePath, string entryPath, string attachmentName, string sourceFile, CancellationToken ct = default)
        => RunCheckedAsync(WithKeyfile(["attachment-import", "-q", "-f"], keyfilePath).Concat([dbPath, entryPath, attachmentName, sourceFile]).ToList(), [password], ct);

    public Task<CliResult> ExportAttachmentAsync(string dbPath, string password, string? keyfilePath, string entryPath, string attachmentName, string outFile, CancellationToken ct = default)
        => RunCheckedAsync(WithKeyfile(["attachment-export", "-q"], keyfilePath).Concat([dbPath, entryPath, attachmentName, outFile]).ToList(), [password], ct);

    public Task<CliResult> ShowAsync(string dbPath, string password, string? keyfilePath, string entryPath, bool showAttachments = true, CancellationToken ct = default)
        => RunCheckedAsync(ShowArgs(dbPath, keyfilePath, entryPath, showAttachments), [password], ct);

    /// <summary>`show` WITHOUT the checked wrapper — returns the failure for existence probes.</summary>
    public Task<CliResult> ShowRawAsync(string dbPath, string password, string? keyfilePath, string entryPath, bool showAttachments = true, CancellationToken ct = default)
        => RunAsync(ShowArgs(dbPath, keyfilePath, entryPath, showAttachments), [password], ct);

    private static List<string> ShowArgs(string dbPath, string? keyfilePath, string entryPath, bool showAttachments)
    {
        var args = new List<string> { "show", "-q" };
        if (showAttachments) args.Add("--show-attachments");
        if (keyfilePath is not null) { args.Add("-k"); args.Add(keyfilePath); }
        args.Add(dbPath);
        args.Add(entryPath);
        return args;
    }

    /// <summary>`ls -R -f` — flat recursive listing. Groups end with '/', entries don't.
    /// keepassxc-cli prints "[empty]" as a sentinel for empty groups — bare when the whole
    /// database is empty, prefixed with the group path otherwise ("Some Group/[empty]");
    /// neither is an entry, both must never leak into the result (0.3.0 beta drill caught
    /// the prefixed variant being parsed as an entry).</summary>
    public async Task<IReadOnlyList<string>> ListEntryPathsAsync(string dbPath, string password, string? keyfilePath, CancellationToken ct = default)
    {
        var result = await RunCheckedAsync(WithKeyfile(["ls", "-q", "-R", "-f"], keyfilePath).Concat([dbPath]).ToList(), [password], ct);
        return result.StdOut
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => !line.EndsWith('/')
                           && line[(line.LastIndexOf('/') + 1)..] != "[empty]")
            .ToList();
    }

    /// <summary>`search` — path-per-line results (verified format). Never prints secret values.</summary>
    public Task<CliResult> SearchAsync(string dbPath, string password, string? keyfilePath, string term, CancellationToken ct = default)
        => RunCheckedAsync(WithKeyfile(["search", "-q"], keyfilePath).Concat([dbPath, term]).ToList(), [password], ct);

    /// <summary>`add -g` — creates the entry with a password generated INSIDE keepassxc-cli;
    /// the value never enters this process. Entry stays unlocked for readback (db password only).</summary>
    public Task<CliResult> AddGeneratedAsync(string dbPath, string password, string? keyfilePath, string entryPath, GenProfile profile, string? notes, CancellationToken ct = default)
    {
        var args = new List<string> { "add", "-q", "-g" };
        args.AddRange(profile.ArgFlags());
        if (!string.IsNullOrEmpty(notes)) { args.Add("--notes"); args.Add(notes); }
        return RunAsync(WithKeyfile(args, keyfilePath).Concat([dbPath, entryPath]).ToList(), [password], ct);
    }

    /// <summary>`add -p` — entry password supplied on stdin (db pw, entry pw, repeat).</summary>
    public Task<CliResult> AddWithValueAsync(string dbPath, string password, string? keyfilePath, string entryPath, Secret entryValue, string? notes, string? username, string? url, CancellationToken ct = default)
    {
        var args = new List<string> { "add", "-q", "-p" };
        if (!string.IsNullOrEmpty(notes)) { args.Add("--notes"); args.Add(notes); }
        if (!string.IsNullOrEmpty(username)) { args.Add("-u"); args.Add(username); }
        if (!string.IsNullOrEmpty(url)) { args.Add("--url"); args.Add(url); }
        return RunAsync(WithKeyfile(args, keyfilePath).Concat([dbPath, entryPath]).ToList(), [password, entryValue.Reveal(), entryValue.Reveal()], ct);
    }

    /// <summary>`edit -p` — replaces the entry password from stdin (db pw, new entry pw, repeat).</summary>
    public Task<CliResult> EditWithValueAsync(string dbPath, string password, string? keyfilePath, string entryPath, Secret entryValue, string? notes, string? username, string? url, CancellationToken ct = default)
    {
        var args = new List<string> { "edit", "-q", "-p" };
        if (notes is not null) { args.Add("--notes"); args.Add(notes); }
        if (!string.IsNullOrEmpty(username)) { args.Add("-u"); args.Add(username); }
        if (!string.IsNullOrEmpty(url)) { args.Add("--url"); args.Add(url); }
        return RunAsync(WithKeyfile(args, keyfilePath).Concat([dbPath, entryPath]).ToList(), [password, entryValue.Reveal(), entryValue.Reveal()], ct);
    }

    /// <summary>`edit -g` — regenerates the entry password inside keepassxc-cli (rotation).</summary>
    public Task<CliResult> EditGeneratedAsync(string dbPath, string password, string? keyfilePath, string entryPath, GenProfile profile, CancellationToken ct = default)
    {
        var args = new List<string> { "edit", "-q", "-g" };
        args.AddRange(profile.ArgFlags());
        return RunAsync(WithKeyfile(args, keyfilePath).Concat([dbPath, entryPath]).ToList(), [password], ct);
    }

    /// <summary>Read ONE entry attribute in clear text (`show -s -a Password`). The value
    /// lands in this process's memory only — for fingerprinting after generation/rotation.
    /// The agent never sees it unless a tool result explicitly says so.</summary>
    public async Task<string> ReadAttributeAsync(string dbPath, string password, string? keyfilePath, string entryPath, string attribute, CancellationToken ct = default)
    {
        var result = await RunCheckedAsync(
            WithKeyfile(["show", "-q", "-s", "-a", attribute], keyfilePath).Concat([dbPath, entryPath]).ToList(), [password], ct);
        return result.StdOut.TrimEnd('\r', '\n');
    }

    /// <summary>`merge` (or `merge --dry-run`). keepassxc-cli prompts for the MAIN password
    /// first, then the STAGING one — both fed as separate stdin lines. NOTE: no -q here —
    /// `-q` silences the merge diff, which is the human's review surface in promote mode.</summary>
    public Task<CliResult> MergeAsync(string mainPath, string mainPassword, string? mainKeyfilePath, string stagingPath, string stagingPassword, bool dryRun, CancellationToken ct = default)
    {
        var args = new List<string> { "merge" };
        if (dryRun) args.Add("--dry-run");
        if (mainKeyfilePath is not null) { args.Add("-k"); args.Add(mainKeyfilePath); }
        args.Add(mainPath);
        args.Add(stagingPath);
        return RunAsync(args, [mainPassword, stagingPassword], ct);
    }

    public Task<CliResult> VersionAsync(CancellationToken ct = default)
        => RunCheckedAsync(["--version"], ct: ct);

    private static List<string> WithKeyfile(IEnumerable<string> args, string? keyfilePath)
    {
        var list = new List<string>(args);
        if (keyfilePath is not null) { list.Add("-k"); list.Add(keyfilePath); }
        return list;
    }
}
