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

        Assert.Equal(0, exit);
        Assert.Contains("Generated", stdout);
        Assert.Contains("Svcs/generated", stdout);

        // The entry exists in staging with a real 20-char password.
        var staged = await h.StagedEntryPathsAsync();
        Assert.Contains("Svcs/generated", staged);
        var value = await h.Cli.ReadAttributeAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Svcs/generated", "Password");
        Assert.Equal(20, value.TrimEnd('\r', '\n').Length);

        // The value never appears in any output — only path/uuid/fingerprint do.
        Assert.DoesNotContain(value.TrimEnd('\r', '\n'), stdout);
        Assert.DoesNotContain(value.TrimEnd('\r', '\n'), stderr);

        // Provenance: generated, fingerprint = sha256 of the actual stored value.
        var prov = ProvenanceStore.Load(h.Paths);
        var rec = Assert.Single(prov.Records);
        Assert.Equal("Svcs/generated", rec.Path);
        Assert.Equal(Origin.Generated, rec.Origin);
        Assert.Equal(Hashing.Sha256Hex(value.TrimEnd('\r', '\n')), rec.FingerprintSha256);

        // The main vault is untouched.
        Assert.False(await h.MainHasEntryAsync("Svcs/generated"));
    }

    [RequiresCliFact]
    public async Task GenerateVerb_Twice_IsClearError_NotSilentReplace()
    {
        using var h = await VaultHarness.CreateAsync();
        var first = await RunVerbAsync(h, null, "generate", "--label", "Svcs/dup");
        Assert.Equal(0, first.Exit);
        var (exit, _, stderr) = await RunVerbAsync(h, null, "generate", "--label", "Svcs/dup");
        Assert.Equal(1, exit);
        Assert.Contains("already exists", stderr);
        Assert.Contains("vault_rotate", stderr);
    }

    [RequiresCliFact]
    public async Task StageVerb_PipedValue_EntersStaging_TaggedPiped_OutputValueFree()
    {
        using var h = await VaultHarness.CreateAsync();
        const string value = "s3cr3t-service-key-9f2a";
        var (exit, stdout, stderr) = await RunVerbAsync(h, value + "\n", "stage", "--label", "Svcs/piped", "--notes", "from service");

        Assert.Equal(0, exit);
        var stored = await h.Cli.ReadAttributeAsync(h.StagingPath, VaultHarness.StagingPassword, null, "Svcs/piped", "Password");
        Assert.Equal(value, stored);

        // the value travelled through the process but was never echoed anywhere
        Assert.DoesNotContain(value, stdout);
        Assert.DoesNotContain(value, stderr);

        var prov = ProvenanceStore.Load(h.Paths);
        var rec = Assert.Single(prov.Records);
        Assert.Equal(Origin.Piped, rec.Origin);
        Assert.Equal(Hashing.Sha256Hex(value), rec.FingerprintSha256);
    }

    [RequiresCliFact]
    public async Task StageVerb_EmptyStdin_Refuses()
    {
        using var h = await VaultHarness.CreateAsync();
        var (exit, _, stderr) = await RunVerbAsync(h, "", "stage", "--label", "Svcs/empty");
        Assert.Equal(1, exit);
        Assert.Contains("Empty stdin", stderr);
        Assert.Empty(ProvenanceStore.Load(h.Paths).Records);
    }

    [RequiresCliFact]
    public async Task AuditVerb_ListsTrackedAndExposedCounts()
    {
        using var h = await VaultHarness.CreateAsync();
        Assert.Equal(0, (await RunVerbAsync(h, null, "generate", "--label", "Svcs/one")).Exit);
        Assert.Equal(0, (await RunVerbAsync(h, "v\n", "stage", "--label", "Svcs/two")).Exit);

        // seed one seen-by-model record the way the MCP tool writes it
        var prov = ProvenanceStore.Load(h.Paths);
        prov.Upsert("Svcs/exposed", null, Origin.SeenByModel, "abc");
        prov.Save(h.Paths);

        var (exit, stdout, _) = await RunVerbAsync(h, null, "audit");
        Assert.Equal(0, exit);
        Assert.Contains("Svcs/one", stdout);
        Assert.Contains("Svcs/exposed", stdout);
        Assert.Contains("exposed to a model: 1", stdout);
        Assert.Contains("rotate or dismiss", stdout);
    }
}
