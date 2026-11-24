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
        // stderr carries the review (stdout stays reserved for the dry-run diff itself);
        // on a real terminal both arrive themed. Prompts keep going through
        // ApproverConsole — its masked-echo / redirected-input contract is untouched.
        var ui = ConsoleUi.ForStderr(cfg);
        ui.Line("keepassxc-mcp promote — human approval for staged vault changes", Tone.AccentStructural);
        // Identity banner: whoever opened this window (human or vault_open_approver), the
        // human can verify WHICH binary is about to prompt for the master password.
        var self = Environment.ProcessPath ?? "";
        ui.Line($"this executable : {self} (v{AppInfo.Version})", Tone.Muted);
        if (self.Length > 0 && File.Exists(self))
        {
            var (selfSha, selfSize) = await Hashing.Sha256FileAsync(self, ct);
            ui.Segments(
                ($"  its sha256    : {selfSha} ({selfSize} B) — ", Tone.Muted),
                ("verify before typing any password", Tone.Accent));
        }
        ui.Line();
        var enterPrompt = "Press Enter in this window to begin the review (nothing has been read or merged): ";
        ui.PromptBox(enterPrompt, "nothing happens before you press Enter here");
        ApproverConsole.WaitEnter(ui.Rich ? "" : enterPrompt);
        ui.Line($"main vault : {cfg.MainVaultPath}" + (cfg.MainHasKeyfile ? " (+ keyfile)" : " (password only)"), Tone.Muted);
        ui.Line($"staging    : {cfg.StagingVaultPath}", Tone.Muted);

        var request = PendingRequest.TryLoad(paths);
        if (request is null)
        {
            ui.Line();
            ui.Line("No pending promotion request. Nothing to do — the agent must call vault_promote first.", Tone.Error);
            return Exit.Error;
        }
        if (!File.Exists(cfg.MainVaultPath))
        {
            ui.Line($"Main vault not found at {cfg.MainVaultPath}. Nothing changed.", Tone.Error);
            return Exit.Error;
        }

        var state = PromoterState.Load(paths);
        var mainMtime = File.GetLastWriteTimeUtc(cfg.MainVaultPath);
        if (state.LastMainMtimeUtc is { } seen && mainMtime != seen)
            ui.Line(
                $"WARNING: main vault file changed since the last promote (mtime {mainMtime:O} vs recorded {seen:O}) — " +
                "something wrote it outside this flow (GUI edit? sync tool?). Review the dry-run diff carefully.", Tone.Warning);
        else if (state.LastMainMtimeUtc is null)
            ui.Line("note: no previous promote is recorded; the main vault may have been edited outside this flow.", Tone.Warning);

        ui.Line();
        ui.Line($"Requested {request.RequestedAtUtc:O} by vault_promote:", Tone.AccentStructural);
        if (ui.Rich)
        {
            // manifest as a table with added/updated markers — what will move, per line.
            var rows = request.Entries.Select(e => new[] { "+", "entry", e.Path, "" }).ToList();
            rows.AddRange(request.Attachments.Select(a => new[] { "+", "attachment", a.EntryPath, $"{a.Name} ({a.SizeBytes} B, sha256 {a.Sha256})" }));
            ui.Table(["", "kind", "target", "attachment"], rows,
                rows.Select(_ => Tone.Added).ToList());
        }
        else
        {
            foreach (var e in request.Entries)
                ui.Line($"  entry      {e.Path}");
            foreach (var a in request.Attachments)
                ui.Line($"  attachment {a.EntryPath} :: {a.Name} ({a.SizeBytes} B, sha256 {a.Sha256})");
        }

        ui.Line();
        var confirmPrompt = $"Merge these {request.Entries.Count} entries into {cfg.MainVaultPath}? [y/N] ";
        ui.PromptBox(confirmPrompt, "y merge · n keep staging · ctrl+c abort");
        if (!ApproverConsole.Confirm(ui.Rich ? "" : confirmPrompt))
        {
            ui.Line("Denied. Staging and vault untouched; request kept.", Tone.Warning);
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
            var passwordPrompt = $"Master password for the main vault (attempt {attempt}/{MaxPasswordAttempts}, input hidden): ";
            ui.PromptBox(passwordPrompt, "typed here only · nothing is written until it passes");
            var entered = ApproverConsole.ReadPassword(ui.Rich ? "" : passwordPrompt);
            if (entered is null)
            {
                ui.Line("Input closed at the password prompt — aborting. Nothing changed.", Tone.Warning);
                return Exit.Denied;
            }
            if (entered.Length == 0)
            {
                ui.Line("Empty password — not tried against the vault.", Tone.Warning);
                continue;
            }
            password = entered;

            ui.Line();
            ui.Line("merge --dry-run (computed now against the current main vault):", Tone.Muted);
            dry = await cli.MergeAsync(cfg.MainVaultPath, password, cfg.MainKeyfilePath, cfg.StagingVaultPath, cfg.StagingPassword, dryRun: true, ct: ct);
            if (dry.Success) break;

            ui.Line("Attempt failed: " + Redact.Apply(dry.FailureSummary, cfg.KnownSecrets), Tone.Error);
            password = string.Empty;
        }
        if (dry is not { Success: true })
        {
            ui.Line($"{MaxPasswordAttempts} password attempts failed — nothing was written; staging and request kept. Run `keepassxc-mcp promote` again when ready.", Tone.Error);
            return Exit.Error;
        }

        try
        {
            // The dry-run diff itself: stdout, raw bytes when piped; +/- diff colors on a terminal.
            ConsoleUi.ForStdout(cfg).Diff(dry.StdOut
                .Replace("\r\n", "\n")
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(line => !line.TrimStart().StartsWith("Enter password to unlock"))
                .Select(line => line.TrimEnd()));

            var merge = await cli.MergeAsync(cfg.MainVaultPath, password, cfg.MainKeyfilePath, cfg.StagingVaultPath, cfg.StagingPassword, dryRun: false, ct: ct);
            if (!merge.Success)
            {
                ui.Line("merge failed: " + Redact.Apply(merge.FailureSummary, cfg.KnownSecrets), Tone.Error);
                ui.Line("The main vault was not written.", Tone.Error);
                return Exit.Error;
            }

            ui.Line();
            ui.Line("Verifying promoted entries in the main vault...", Tone.Muted);
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
                ui.Line("WARNING: merge ran but verification FAILED:", Tone.Warning);
                foreach (var p in problems) ui.Line("  - " + p, Tone.Error);
                ui.Line("Staging was NOT flushed and the request is kept — inspect, then re-run promote.", Tone.Warning);
                return Exit.Error;
            }

            await new StagingMaintenance(cli, cfg).FlushAsync(ct);
            state.LastPromotedUtc = DateTimeOffset.UtcNow;
            state.LastMainMtimeUtc = File.GetLastWriteTimeUtc(cfg.MainVaultPath);
            state.LastPromotedEntryCount = request.Entries.Count;
            state.Save(paths);
            PendingRequest.Clear(paths);

            ui.Line($"OK: {request.Entries.Count} entries promoted to the main vault; staging flushed; pending request cleared.", Tone.Success);
            return Exit.Ok;
        }
        finally
        {
            password = string.Empty;
        }
    }
}
