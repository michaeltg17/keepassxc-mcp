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
        using var h = await VaultHarness.CreateAsync();
        var (exit, stdout, stderr) = await RunVerbAsync(h, null, "generate", "--label", "Svcs/generated", "--length", "20");

        exit.Should().Be(0);
        stdout.Should().Contain("Generated").And.Contain("Svcs/generated");

        // The entry exists in staging with a real 20-char password.
        var staged = await h.StagedEntryPathsAsync();
        staged.Should().Contain("Svcs/generated");
        var value = (await h.Cli.ReadAttributeAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Svcs/generated", "Password")).TrimEnd('\r', '\n');
        value.Should().HaveLength(20);

        // The value never appears in any output — only path/uuid/fingerprint do.
        stdout.Should().NotContain(value);
        stderr.Should().NotContain(value);

        // Provenance: generated, fingerprint = sha256 of the actual stored value.
        var prov = ProvenanceStore.Load(h.Paths);
        var rec = Assert.Single(prov.Records);
        rec.Path.Should().Be("Svcs/generated");
        rec.Origin.Should().Be(Origin.Generated);
        rec.FingerprintSha256.Should().Be(Hashing.Sha256Hex(value));

        // The main vault is untouched.
        (await h.MainHasEntryAsync("Svcs/generated")).Should().BeFalse();
    }

    [RequiresCliFact]
    public async Task GenerateVerb_Twice_IsClearError_NotSilentReplace()
    {
        using var h = await VaultHarness.CreateAsync();
        var first = await RunVerbAsync(h, null, "generate", "--label", "Svcs/dup");
        first.Exit.Should().Be(0);
        var (exit, _, stderr) = await RunVerbAsync(h, null, "generate", "--label", "Svcs/dup");
        exit.Should().Be(1);
        stderr.Should().Contain("already exists").And.Contain("vault_rotate");
    }

    [RequiresCliFact]
    public async Task StageVerb_PipedValue_EntersStaging_TaggedPiped_OutputValueFree()
    {
        using var h = await VaultHarness.CreateAsync();
        const string value = "s3cr3t-service-key-9f2a";
        var (exit, stdout, stderr) = await RunVerbAsync(h, value + "\n", "stage", "--label", "Svcs/piped", "--notes", "from service");

        exit.Should().Be(0);
        var stored = await h.Cli.ReadAttributeAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Svcs/piped", "Password");
        stored.Should().Be(value);

        // the value travelled through the process but was never echoed anywhere
        stdout.Should().NotContain(value);
        stderr.Should().NotContain(value);

        var prov = ProvenanceStore.Load(h.Paths);
        var rec = Assert.Single(prov.Records);
        rec.Origin.Should().Be(Origin.Piped);
        rec.FingerprintSha256.Should().Be(Hashing.Sha256Hex(value));
    }

    [RequiresCliFact]
    public async Task StageVerb_EmptyStdin_Refuses()
    {
        using var h = await VaultHarness.CreateAsync();
        var (exit, _, stderr) = await RunVerbAsync(h, "", "stage", "--label", "Svcs/empty");
        exit.Should().Be(1);
        stderr.Should().Contain("Empty stdin");
        ProvenanceStore.Load(h.Paths).Records.Should().BeEmpty();
    }

    [RequiresCliFact]
    public async Task AuditVerb_ListsTrackedAndExposedCounts()
    {
        using var h = await VaultHarness.CreateAsync();
        (await RunVerbAsync(h, null, "generate", "--label", "Svcs/one")).Exit.Should().Be(0);
        (await RunVerbAsync(h, "v\n", "stage", "--label", "Svcs/two")).Exit.Should().Be(0);

        // seed one seen-by-model record the way the MCP tool writes it
        var prov = ProvenanceStore.Load(h.Paths);
        prov.Upsert("Svcs/exposed", null, Origin.SeenByModel, "abc");
        prov.Save(h.Paths);

        var (exit, stdout, _) = await RunVerbAsync(h, null, "audit");
        exit.Should().Be(0);
        stdout.Should().Contain("Svcs/one").And.Contain("Svcs/exposed")
            .And.Contain("exposed to a model: 1").And.Contain("rotate or dismiss");
    }
}
