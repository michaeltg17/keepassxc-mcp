using System.Diagnostics;
using System.Text;
using KeePassXCMcp.Infra;
using KeePassXCMcp.Tools;

namespace KeePassXCMcp.Tests;

/// <summary>End-to-end rich-console tests (issue #24). Every child process here runs
/// with piped stdio like the rest of the suite, but with KEEPASSXC_MCP_RICH=1 forcing
/// the themed path — the hook that lets the e2e suite assert the CONTENT of rich
/// surfaces (entry paths, redaction markers, section titles, hints). No pixel asserts:
/// what matters is that the real terminal path carries the same truth as the plain one
/// (and never leaks secret values), and that without the flag the plain bytes win.</summary>
public class ConsoleUiTests
{
    private static async Task<(int Exit, string StdOut, string StdErr)> RunAsync(
        VaultHarness harness, bool rich, string mode, string? stdin = null, VaultConfig? configOverride = null)
    {
        if (configOverride is not null)
            harness.WriteConfigFile(configOverride);

        var psi = new ProcessStartInfo
        {
            FileName = VaultHarness.ServerExePath,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, // the rich path writes UTF-8 (box glyphs, ·)
            StandardErrorEncoding = Encoding.UTF8,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in mode.Split(' ')) psi.ArgumentList.Add(a);
        psi.Environment["KEEPASSXC_MCP_CONFIG"] = harness.Paths.ConfigFile;
        if (rich) psi.Environment["KEEPASSXC_MCP_RICH"] = "1";

        using var proc = Process.Start(psi)!;
        if (stdin is not null)
            foreach (var line in stdin.Split('\n'))
                proc.StandardInput.WriteLine(line);
        proc.StandardInput.Close();
        var stdout = await proc.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var stderr = await proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);
        return (proc.ExitCode, stdout, stderr);
    }

    /// <summary>Strip SGR color escapes before asserting: the suite checks CONTENT (which
    /// words, which markers, which box glyphs appear) — the escapes between them are
    /// decoration and may split at any point. The separate raw-stream checks below still
    /// prove the escapes are there (rich on) or absent (plain path wins).</summary>
    private static string Content(string s) =>
        System.Text.RegularExpressions.Regex.Replace(s, @"\u001b\[[0-9;]*m", "");

    [RequiresCliFact]
    public async Task RichStatus_DefaultTheme_SectionsAndRedaction_NoSecrets()
    {
        // given: a harness with staged content and the DEFAULT theme (no consoleTheme key at all)
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "RichEntry", "themed status probe");

        // when: `status` runs forced-rich on piped stdio, then: the same truths arrive —
        // section structure, entry paths, the redaction marker — with ANSI color in place.
        var (exit, stdout, _) = await RunAsync(h, rich: true, "status");
        exit.Should().Be(0);
        stdout.Should().Contain("\u001b[");                          // themed rendering is on
        var text = Content(stdout);                                 // then the content it carries
        text.Should().Contain("Setup").And.Contain("Staging").And.Contain("Sessions")
            .And.Contain("Inbox/RichEntry").And.Contain("[REDACTED");
        text.Should().NotContain(VaultHarness.StagingPassword);     // redaction is content, not color
    }

    [RequiresCliFact]
    public async Task RichStatus_StrataTheme_DrawsTitledCards()
    {
        // given: consoleTheme: "strata" in config
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "CardEntry", "card rendering probe");

        // when: `status` runs forced-rich, then: the card layout appears (titled panels)
        // while the SAME content — entry paths and [REDACTED] — is still in there.
        var (exit, stdout, _) = await RunAsync(h, rich: true, "status",
            configOverride: h.Config with { ConsoleTheme = "strata" });
        exit.Should().Be(0);
        Content(stdout).Should().Contain("┌").And.Contain("Setup").And.Contain("Sessions")
            .And.Contain("Inbox/CardEntry").And.Contain("[REDACTED");
        Content(stdout).Should().NotContain(VaultHarness.StagingPassword);
    }

    [RequiresCliFact]
    public async Task RichStatus_UnknownThemeName_FallsBackToDefault()
    {
        // given: a nonsense theme value — the setting picks one of two names, anything
        // else means the default, quietly, no error no crash
        using var h = await VaultHarness.CreateAsync();

        var (exit, stdout, _) = await RunAsync(h, rich: true, "status",
            configOverride: h.Config with { ConsoleTheme = "definitely-not-a-theme" });
        exit.Should().Be(0);
        Content(stdout).Should().Contain("Setup").And.Contain("app version").And.Contain("[REDACTED");
    }

    [RequiresCliFact]
    public async Task NoForceNoTerminal_PlainBytesWin_EscapesNeverAppear()
    {
        // given/when: `status` runs exactly as every other test runs a child (piped,
        // no forced rich, NO env override), then: the byte shape is today's — aligned
        // plain keys, no ANSI anywhere — the theme never reaches a machine consumer.
        using var h = await VaultHarness.CreateAsync();
        var (exit, stdout, _) = await RunAsync(h, rich: false, "status");
        exit.Should().Be(0);
        stdout.Should().Contain("app version   : " + AppInfo.Version) // exact plain alignment
            .And.NotContain("\u001b[");
    }

    [RequiresCliFact]
    public async Task RichAudit_ExposedRowsAndRemedy_NoSecretValues()
    {
        // given: one seen-by-model record (the audit's reason to exist)
        using var h = await VaultHarness.CreateAsync();
        var prov = ProvenanceStore.Load(h.Paths);
        prov.Upsert("Svcs/Exposed", null, Origin.SeenByModel, "fp1");
        prov.Save(h.Paths);

        // when: `audit` runs forced-rich, then: the table carries the path, the origin,
        // and the remedy wording — content-level only, never secret values.
        var (exit, stdout, _) = await RunAsync(h, rich: true, "audit");
        exit.Should().Be(0);
        Content(stdout).Should().Contain("tracked secrets: 1")
            .And.Contain("Svcs/Exposed").And.Contain(Origin.SeenByModel).And.Contain("rotate or dismiss");
    }

    [RequiresCliFact]
    public async Task RichPromote_DecisionHintsAndDiff_FullFlowStillWorks()
    {
        // given: staged content and a recorded request
        using var h = await VaultHarness.CreateAsync();
        await h.StageAsync("Inbox", "ThemedPromote", "rich approver probe");
        await h.RecordPromotionRequestAsync();

        // when: the human flow runs forced-rich (confirm + password still read from the
        // stream — the masked/redirected-input contract is untouched), then: it merges,
        // and the decision chrome (identity line, key hints, manifest) is present.
        var (pExit, pStdout, pStderr) = await RunAsync(h, rich: true, "promote",
            stdin: "y\n" + VaultHarness.MainPassword);
        pExit.Should().Be((int)Promoter.Exit.Ok);
        Content(pStdout).Should().MatchRegex("Added:|Creating missing"); // the diff still says what moved
        var joined = Content(pStderr + pStdout);
        joined.Should().Contain("ThemedPromote")
            .And.Contain("verify before typing any password")       // identity banner emphasis
            .And.Contain("y merge · n keep staging · ctrl+c abort"); // the decision-step key hint
        (await h.MainHasEntryAsync("Inbox/ThemedPromote")).Should().BeTrue();
        (await h.StagedEntryPathsAsync()).Should().BeEmpty();
    }

    [RequiresCliFact]
    public async Task RichReader_ReadsOnlyChrome_AndHonestCloseSummary()
    {
        // given: a reader forced-rich, started against a dead server pid so the orphan
        // guard closes it right after unlock
        using var h = await VaultHarness.CreateAsync();
        var psi = new ProcessStartInfo
        {
            FileName = VaultHarness.ServerExePath,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("reader");
        psi.ArgumentList.Add("--server");
        psi.ArgumentList.Add("999999");
        psi.Environment["KEEPASSXC_MCP_CONFIG"] = h.Paths.ConfigFile;
        psi.Environment["KEEPASSXC_MCP_RICH"] = "1";

        using var proc = Process.Start(psi)!;
        proc.StandardInput.WriteLine(VaultHarness.MainPassword);
        proc.StandardInput.Close();
        var stderr = await proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);

        // then: the READ-session identity is unmistakable, the password prompt explains
        // itself, the close says why — and the summary states duration/reads honestly.
        proc.ExitCode.Should().Be(0);
        Content(stderr).Should().Contain("reads only").And.Contain("verify before typing any password")
            .And.Contain("orphan guard").And.Contain("Read session summary");
    }

    [RequiresCliFact]
    public async Task RichUnknownMode_ErrorAndUsageAreThemedButTextual()
    {
        // given/when: an unknown mode forced-rich, then: same usage block as plain —
        // the mode list is complete — with the error honestly red (content, not color,
        // is what we can assert).
        using var h = await VaultHarness.CreateAsync();
        var (exit, _, stderr) = await RunAsync(h, rich: true, "frobnicate");
        exit.Should().Be(2);
        Content(stderr).Should().Contain("Unknown mode: frobnicate")
            .And.Contain("keepassxc-mcp promote").And.Contain("usage:");
    }
}
