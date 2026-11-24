using KeePassXCMcp.Infra;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace KeePassXCMcp.Tests;

/// <summary>The staging delete flow (vault_staged_remove): recycle-only disposition,
/// the exact-path confirm knob, and the sidecar cleanup (manifest record + provenance).
/// Talks the real MCP protocol to the built exe; recycle-bin presence is proven with a
/// RAW keepassxc-cli search (listings deliberately hide recycled entries — that absence
/// is the expected behavior, not proof).</summary>
public class StagedRemoveTests
{
    private static string Text(CallToolResult result) =>
        string.Join("\n", result.Content.OfType<TextContentBlock>().Select(c => c.Text));

    private static async Task<McpClient> ConnectAsync(VaultHarness harness)
    {
        var transport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "keepassxc-mcp",
            Command = VaultHarness.ServerExePath,
            Arguments = ["mcp"],
            EnvironmentVariables = new Dictionary<string, string?> { ["KEEPASSXC_MCP_CONFIG"] = harness.Paths.ConfigFile },
        });
        return await McpClient.CreateAsync(transport);
    }

    [RequiresCliFact]
    public async Task Stage_Promote_Request_Then_Remove_GoneFromEverySidecar()
    {
        using var harness = await VaultHarness.CreateAsync();
        await using var client = await ConnectAsync(harness);

        var stage = Text(await client.CallToolAsync("vault_stage_value", new Dictionary<string, object?>
        {
            ["label"] = "Inbox/RemoveMe",
            ["value"] = "doomed-secret-value-1",
        }));
        stage.Should().Contain("Staged into sandbox");

        var promote = Text(await client.CallToolAsync("vault_promote", new Dictionary<string, object?>()));
        promote.Should().Contain("Promotion request recorded");

        var remove = Text(await client.CallToolAsync("vault_staged_remove", new Dictionary<string, object?>
        {
            ["entryPath"] = "Inbox/RemoveMe",
            ["confirm"] = "Inbox/RemoveMe",
        }));
        remove.Should().Contain("RECYCLED, not purged").And.Contain("recycled");

        // vault_list_staged no longer shows it, and neither does the promotion manifest.
        var list = Text(await client.CallToolAsync("vault_list_staged", new Dictionary<string, object?>()));
        list.Should().NotContain("Inbox/RemoveMe");
        var pending = PendingRequest.TryLoad(harness.Paths);
        pending.Should().NotBeNull();
        pending!.Entries.Should().NotContain(e => e.Path == "Inbox/RemoveMe");

        // Provenance record dropped.
        ProvenanceStore.Load(harness.Paths).Records.Should().NotContain(r => r.Path == "Inbox/RemoveMe");

        // The recycle-bin claim, proven RAW: keepassxc-cli search still matches the entry
        // under a Recycle Bin path (a raw ls would not show it — that is the filter's job).
        var search = await harness.Cli.SearchAsync(harness.StagingPath, VaultHarness.StagingPassword, null, "RemoveMe");
        Assert.True(search.Success, search.FailureSummary);
        search.StdOut.Should().Contain("Recycle Bin").And.Contain("RemoveMe");
    }

    [RequiresCliFact]
    public async Task Remove_ConfirmMismatch_Refuses_EntryAndSidecarsUntouched()
    {
        using var harness = await VaultHarness.CreateAsync();
        await harness.StageAsync("Inbox", "KeepMe", "notes");
        var prov = ProvenanceStore.Load(harness.Paths);
        prov.Upsert("Inbox/KeepMe", null, Origin.SeenByModel, "fp");
        prov.Save(harness.Paths);

        await using var client = await ConnectAsync(harness);
        var reply = Text(await client.CallToolAsync("vault_staged_remove", new Dictionary<string, object?>
        {
            ["entryPath"] = "Inbox/KeepMe",
            ["confirm"] = "Inbox/WRONG",
        }));
        reply.Should().Contain("Error").And.Contain("confirmation does not match");

        (await harness.StagedEntryPathsAsync()).Should().Contain("Inbox/KeepMe");
        ProvenanceStore.Load(harness.Paths).Records.Should().Contain(r => r.Path == "Inbox/KeepMe");
    }

    [RequiresCliFact]
    public async Task Remove_MistypedPath_ErrorsWithCurrentListing()
    {
        using var harness = await VaultHarness.CreateAsync();
        await harness.StageAsync("Inbox", "RealEntry", "notes");

        await using var client = await ConnectAsync(harness);
        var reply = Text(await client.CallToolAsync("vault_staged_remove", new Dictionary<string, object?>
        {
            ["entryPath"] = "Inbox/NoSuchEntry",
            ["confirm"] = "Inbox/NoSuchEntry",
        }));
        reply.Should().Contain("Error").And.Contain("is not in staging").And.Contain("Inbox/RealEntry"); // the current staged listing comes with the error

        (await harness.StagedEntryPathsAsync()).Should().Contain("Inbox/RealEntry"); // nothing changed
    }

    [RequiresCliFact]
    public async Task Remove_ThenRestage_SamePath_CleanProvenanceUpsert()
    {
        using var harness = await VaultHarness.CreateAsync();
        await using var client = await ConnectAsync(harness);

        await client.CallToolAsync("vault_stage_value", new Dictionary<string, object?>
        {
            ["label"] = "Inbox/ReStaged",
            ["value"] = "first-value-aaa",
        });
        var remove = Text(await client.CallToolAsync("vault_staged_remove", new Dictionary<string, object?>
        {
            ["entryPath"] = "Inbox/ReStaged",
            ["confirm"] = "Inbox/ReStaged",
        }));
        remove.Should().Contain("RECYCLED");
        ProvenanceStore.Load(harness.Paths).Records.Should().BeEmpty();

        var restage = Text(await client.CallToolAsync("vault_stage_value", new Dictionary<string, object?>
        {
            ["label"] = "Inbox/ReStaged",
            ["value"] = "second-value-bbb",
        }));
        restage.Should().Contain("Staged into sandbox");

        // One fresh record for the new value — no stale fingerprint, no retired leftovers.
        var rec = Assert.Single(ProvenanceStore.Load(harness.Paths).Records);
        rec.Path.Should().Be("Inbox/ReStaged");
        rec.Origin.Should().Be(Origin.SeenByModel);
        rec.RetiredFingerprints.Should().BeEmpty();
        rec.FingerprintSha256.Should().NotBe(Hashing.Sha256Hex("first-value-aaa"));
        rec.FingerprintSha256.Should().Be(Hashing.Sha256Hex("second-value-bbb"));
    }
}
