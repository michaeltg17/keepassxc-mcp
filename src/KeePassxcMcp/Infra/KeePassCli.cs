using System.Diagnostics;
using System.Text;

namespace KeePassxcMcp.Infra;

public sealed record CliResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Success => ExitCode == 0;

    /// <summary>Short failure description safe for users/logs (never contains stdin).</summary>
    public string FailureSummary =>
        $"keepassxc-cli exited {ExitCode}: {Shorten(StdErr.Trim().Length > 0 ? StdErr.Trim() : StdOut.Trim())}";

    private static string Shorten(string s) => s.Length <= 400 ? s : s[..400] + "…";
}

public sealed class KeePassCliException(string message) : Exception(message);

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

    /// <summary>`ls -R -f` — flat recursive listing. Groups end with '/', entries don't.</summary>
    public async Task<IReadOnlyList<string>> ListEntryPathsAsync(string dbPath, string password, string? keyfilePath, CancellationToken ct = default)
    {
        var result = await RunCheckedAsync(WithKeyfile(["ls", "-q", "-R", "-f"], keyfilePath).Concat([dbPath]).ToList(), [password], ct);
        return result.StdOut
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => !line.EndsWith('/') && line != "[empty]") // "[empty]" is keepassxc-cli's sentinel for empty groups
            .ToList();
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
