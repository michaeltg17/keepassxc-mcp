using KeePassXCMcp.Tools;

namespace KeePassXCMcp.Infra;

/// <summary>
/// The HUMAN side (`keepassxc-mcp promote`), run in a real terminal. This is the ONLY
/// code path in the whole product that ever touches the main vault password — and it goes
/// from the masked console prompt straight into keepassxc-cli's stdin. The agent side
/// (MCP stdio server) can neither see, request, nor receive it.
/// </summary>
public static class Promoter
{
    /// <summary>The documented exit-code contract of `keepassxc-mcp promote` (see the wiki
    /// "Refusals are no-ops" table). Everything internal speaks this type; ints appear only
    /// at the OS process boundary. (`promote` with an unreadable config exits 2 from
    /// Program.cs like every other mode — a usage error, outside this contract.)</summary>
    public enum Exit
    {
        /// <summary>Merged, verified, staging flushed, request cleared.</summary>
        Ok = 0,
        /// <summary>Error: no request, CLI/merge failure, 3 failed password attempts, or post-merge verification problems.</summary>
        Error = 1,
        /// <summary>The human denied or the input closed (EOF) — a clean no-op.</summary>
        Denied = 2,
        /// <summary>Ctrl+C at a terminal prompt.</summary>
        Cancelled = 130,
    }

    public static async Task<Exit> RunAsync(VaultConfig cfg, ConfigPaths paths, KeePassCli cli, CancellationToken ct = default)
    {
        Console.Error.WriteLine("keepassxc-mcp promote — human approval for staged vault changes");
        // Identity banner: whoever opened this window (human or vault_open_approver), the
        // human can verify WHICH binary is about to prompt for the master password.
        var self = Environment.ProcessPath ?? "";
        Console.Error.WriteLine($"this executable : {self} (v{AppInfo.Version})");
        if (self.Length > 0 && File.Exists(self))
        {
            var (selfSha, selfSize) = await Hashing.Sha256FileAsync(self, ct);
            Console.Error.WriteLine($"  its sha256    : {selfSha} ({selfSize} B) — verify before typing any password");
        }
        Console.Error.WriteLine();
        ApproverConsole.WaitEnter("Press Enter in this window to begin the review (nothing has been read or merged): ");
        Console.Error.WriteLine($"main vault : {cfg.MainVaultPath}" + (cfg.MainHasKeyfile ? " (+ keyfile)" : " (password only)"));
        Console.Error.WriteLine($"staging    : {cfg.StagingVaultPath}");

        var request = PendingRequest.TryLoad(paths);
        if (request is null)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("No pending promotion request. Nothing to do — the agent must call vault_promote first.");
            return Exit.Error;
        }
        if (!File.Exists(cfg.MainVaultPath))
        {
            Console.Error.WriteLine($"Main vault not found at {cfg.MainVaultPath}. Nothing changed.");
            return Exit.Error;
        }

        var state = PromoterState.Load(paths);
        var mainMtime = File.GetLastWriteTimeUtc(cfg.MainVaultPath);
        if (state.LastMainMtimeUtc is { } seen && mainMtime != seen)
            Console.Error.WriteLine(
                $"WARNING: main vault file changed since the last promote (mtime {mainMtime:O} vs recorded {seen:O}) — " +
                "something wrote it outside this flow (GUI edit? sync tool?). Review the dry-run diff carefully.");
        else if (state.LastMainMtimeUtc is null)
            Console.Error.WriteLine("note: no previous promote is recorded; the main vault may have been edited outside this flow.");

        Console.Error.WriteLine();
        Console.Error.WriteLine($"Requested {request.RequestedAtUtc:O} by vault_promote:");
        foreach (var e in request.Entries)
            Console.Error.WriteLine($"  entry      {e.Path}");
        foreach (var a in request.Attachments)
            Console.Error.WriteLine($"  attachment {a.EntryPath} :: {a.Name} ({a.SizeBytes} B, sha256 {a.Sha256})");

        Console.Error.WriteLine();
        if (!ApproverConsole.Confirm($"Merge these {request.Entries.Count} entries into {cfg.MainVaultPath}? [y/N] "))
        {
            Console.Error.WriteLine("Denied. Staging and vault untouched; request kept.");
            return Exit.Denied;
        }

        // Password attempts: the dry-run doubles as a READ-ONLY credential probe —
        // nothing is written to the main vault until a password has passed it.
        // A wrong or empty password consumes an attempt and re-prompts (max 3).
        // EOF at this prompt cannot be re-read, so it aborts as a clean no-op.
        const int MaxPasswordAttempts = 3;
        var password = string.Empty;
        CliResult? dry = null;
        for (var attempt = 1; attempt <= MaxPasswordAttempts; attempt++)
        {
            var entered = ApproverConsole.ReadPassword($"Master password for the main vault (attempt {attempt}/{MaxPasswordAttempts}, input hidden): ");
            if (entered is null)
            {
                Console.Error.WriteLine("Input closed at the password prompt — aborting. Nothing changed.");
                return Exit.Denied;
            }
            if (entered.Length == 0)
            {
                Console.Error.WriteLine("Empty password — not tried against the vault.");
                continue;
            }
            password = entered;

            Console.Error.WriteLine();
            Console.Error.WriteLine("merge --dry-run (computed now against the current main vault):");
            dry = await cli.MergeAsync(cfg.MainVaultPath, password, cfg.MainKeyfilePath, cfg.StagingVaultPath, cfg.StagingPassword, dryRun: true, ct: ct);
            if (dry.Success) break;

            Console.Error.WriteLine("Attempt failed: " + Redact.Apply(dry.FailureSummary, cfg.KnownSecrets));
            password = string.Empty;
        }
        if (dry is not { Success: true })
        {
            Console.Error.WriteLine($"{MaxPasswordAttempts} password attempts failed — nothing was written; staging and request kept. Run `keepassxc-mcp promote` again when ready.");
            return Exit.Error;
        }

        try
        {
            Console.WriteLine(string.Join("\n", dry.StdOut
                .Replace("\r\n", "\n")
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(line => !line.TrimStart().StartsWith("Enter password to unlock"))
                .Select(line => line.TrimEnd())));

            var merge = await cli.MergeAsync(cfg.MainVaultPath, password, cfg.MainKeyfilePath, cfg.StagingVaultPath, cfg.StagingPassword, dryRun: false, ct: ct);
            if (!merge.Success)
            {
                Console.Error.WriteLine("merge failed: " + Redact.Apply(merge.FailureSummary, cfg.KnownSecrets));
                Console.Error.WriteLine("The main vault was not written.");
                return Exit.Error;
            }

            Console.Error.WriteLine();
            Console.Error.WriteLine("Verifying promoted entries in the main vault...");
            var problems = new List<string>();
            foreach (var entry in request.Entries)
            {
                var show = await cli.ShowRawAsync(cfg.MainVaultPath, password, cfg.MainKeyfilePath, entry.Path, ct: ct);
                if (!show.Success)
                {
                    problems.Add($"entry not found after merge: {entry.Path}");
                    continue;
                }
                var parsed = ShowParser.Parse(show.StdOut);
                foreach (var expected in request.Attachments.Where(a => a.EntryPath == entry.Path))
                {
                    if (parsed.Attachments.All(a => a.Name != expected.Name))
                    {
                        problems.Add($"attachment missing after merge: {expected.Name} on {entry.Path}");
                        continue;
                    }
                    var (sha, size) = await StagingOps.HashStoredAttachmentAsync(cfg, cli, cfg.MainVaultPath, password, cfg.MainKeyfilePath, entry.Path, expected.Name, ct);
                    if (sha != expected.Sha256 || size != expected.SizeBytes)
                        problems.Add($"attachment hash/size mismatch: {expected.Name} on {entry.Path} (got {size} B, sha256 {sha})");
                }
            }
            if (problems.Count > 0)
            {
                Console.Error.WriteLine("WARNING: merge ran but verification FAILED:");
                foreach (var p in problems) Console.Error.WriteLine("  - " + p);
                Console.Error.WriteLine("Staging was NOT flushed and the request is kept — inspect, then re-run promote.");
                return Exit.Error;
            }

            await new StagingMaintenance(cli, cfg).FlushAsync(ct);
            state.LastPromotedUtc = DateTimeOffset.UtcNow;
            state.LastMainMtimeUtc = File.GetLastWriteTimeUtc(cfg.MainVaultPath);
            state.LastPromotedEntryCount = request.Entries.Count;
            state.Save(paths);
            PendingRequest.Clear(paths);

            Console.Error.WriteLine($"OK: {request.Entries.Count} entries promoted to the main vault; staging flushed; pending request cleared.");
            return Exit.Ok;
        }
        finally
        {
            password = string.Empty;
        }
    }
}
