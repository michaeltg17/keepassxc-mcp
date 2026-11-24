using System.Diagnostics;
using KeePassXCMcp.Infra;

namespace KeePassXCMcp.Tests;

/// <summary>End-to-end tests for the CLI verbs of SPEC.md flows F1/F2.1 (generate, stage
/// from stdin) and the audit view. Real binary, real keepassxc-cli — the whole point of
/// these flows is that the VALUE never appears in stdout/stderr, which is asserted.</summary>
public class SecretFlowsTests
{
    private static async Task<(int Exit, string StdOut, string StdErr)> RunVerbAsync(
        VaultHarness h, string? stdin, params string[] argv)
    {
        var psi = new ProcessStartInfo
        {
            FileName = VaultHarness.ServerExePath,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in argv) psi.ArgumentList.Add(a);
        psi.Environment["KEEPASSXC_MCP_CONFIG"] = h.Paths.ConfigFile;

        using var proc = Process.Start(psi)!;
        if (stdin is not null) await proc.StandardInput.WriteAsync(stdin);
        proc.StandardInput.Close();
        var stdout = await proc.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var stderr = await proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);
        return (proc.ExitCode, stdout, stderr);
    }

    [RequiresCliFact]
    public async Task GenerateVerb_StagesGeneratedValue_ProvenanceGenerated_OutputValueFree()
    {
        // when: the `generate` verb creates a staged entry with a 20-char value…
        using var h = await VaultHarness.CreateAsync();
        var (exit, stdout, stderr) = await RunVerbAsync(h, null, "generate", "--label", "Svcs/generated", "--length", "20");

        // then: it succeeds and identifies the entry by label…
        exit.Should().Be(0);
        stdout.Should().Contain("Generated").And.Contain("Svcs/generated");

        // …and the entry really exists in staging with a real 20-char password…
        var staged = await h.StagedEntryPathsAsync();
        staged.Should().Contain("Svcs/generated");
        var value = (await h.Cli.ReadAttributeAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Svcs/generated", "Password")).TrimEnd('\r', '\n');
        value.Should().HaveLength(20);

        // …but the value never appears in any output — only path/uuid/fingerprint do,
        // because keepassxc-cli generated it inside its own process
        stdout.Should().NotContain(value);
        stderr.Should().NotContain(value);

        // and: provenance records it as generated, fingerprint = sha256 of the actual
        // stored value (the audit can later prove what was never seen)
        var prov = ProvenanceStore.Load(h.Paths);
        var rec = Assert.Single(prov.Records);
        rec.Path.Should().Be("Svcs/generated");
        rec.Origin.Should().Be(Origin.Generated);
        rec.FingerprintSha256.Should().Be(Hashing.Sha256Hex(value));

        // and: the main vault is untouched — staging is the only thing this verb writes
        (await h.MainHasEntryAsync("Svcs/generated")).Should().BeFalse();
    }

    [RequiresCliFact]
    public async Task GenerateVerb_Twice_IsClearError_NotSilentReplace()
    {
        // given: a label that was already generated once
        using var h = await VaultHarness.CreateAsync();
        var first = await RunVerbAsync(h, null, "generate", "--label", "Svcs/dup");
        first.Exit.Should().Be(0);

        // when: generate runs again for the SAME label, then: exit 1 and an error that
        // explains the situation and names the intended remedy — never a silent overwrite
        var (exit, _, stderr) = await RunVerbAsync(h, null, "generate", "--label", "Svcs/dup");
        exit.Should().Be(1);
        stderr.Should().Contain("already exists").And.Contain("vault_rotate");
    }

    [RequiresCliFact]
    public async Task StageVerb_PipedValue_EntersStaging_TaggedPiped_OutputValueFree()
    {
        // given: a secret the agent has never seen, available only on the command pipe
        using var h = await VaultHarness.CreateAsync();
        const string value = "s3cr3t-service-key-9f2a";

        // when: it is piped through the `stage` verb, then: staging holds exactly that
        // value — and the value is never echoed on stdout or stderr on the way in
        var (exit, stdout, stderr) = await RunVerbAsync(h, value + "\n", "stage", "--label", "Svcs/piped", "--notes", "from service");
        exit.Should().Be(0);
        var stored = await h.Cli.ReadAttributeAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Svcs/piped", "Password");
        stored.Should().Be(value);
        stdout.Should().NotContain(value);
        stderr.Should().NotContain(value);

        // and: provenance tags the flow honestly as `piped` with the true fingerprint —
        // no rotation prompt needed, because no model ever saw it
        var prov = ProvenanceStore.Load(h.Paths);
        var rec = Assert.Single(prov.Records);
        rec.Origin.Should().Be(Origin.Piped);
        rec.FingerprintSha256.Should().Be(Hashing.Sha256Hex(value));
    }

    [RequiresCliFact]
    public async Task StageVerb_EmptyStdin_Refuses()
    {
        // when: `stage` is invoked but stdin carries nothing, then: exit 1 with a clear
        // reason — and an empty provenance store, not a half-written record
        using var h = await VaultHarness.CreateAsync();
        var (exit, _, stderr) = await RunVerbAsync(h, "", "stage", "--label", "Svcs/empty");
        exit.Should().Be(1);
        stderr.Should().Contain("Empty stdin");
        ProvenanceStore.Load(h.Paths).Records.Should().BeEmpty();
    }

    [RequiresCliFact]
    public async Task AuditVerb_ListsTrackedAndExposedCounts()
    {
        // given: two entries created by the honest flows (generated, piped) plus one
        // seeded seen-by-model record — exactly the state the audit exists to report
        using var h = await VaultHarness.CreateAsync();
        (await RunVerbAsync(h, null, "generate", "--label", "Svcs/one")).Exit.Should().Be(0);
        (await RunVerbAsync(h, "v\n", "stage", "--label", "Svcs/two")).Exit.Should().Be(0);

        var prov = ProvenanceStore.Load(h.Paths);
        prov.Upsert("Svcs/exposed", null, Origin.SeenByModel, "abc");
        prov.Save(h.Paths);

        // when: `audit` is run, then: all three tracked entries are listed, the exposure
        // count is exact (1), and the remedy wording is present
        var (exit, stdout, _) = await RunVerbAsync(h, null, "audit");
        exit.Should().Be(0);
        stdout.Should().Contain("Svcs/one").And.Contain("Svcs/exposed")
            .And.Contain("exposed to a model: 1").And.Contain("rotate or dismiss");
    }
}
