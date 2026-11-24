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
        Assert.Contains("Staged into sandbox", stage);

        var promote = Text(await client.CallToolAsync("vault_promote", new Dictionary<string, object?>()));
        Assert.Contains("Promotion request recorded", promote);

        var remove = Text(await client.CallToolAsync("vault_staged_remove", new Dictionary<string, object?>
        {
            ["entryPath"] = "Inbox/RemoveMe",
            ["confirm"] = "Inbox/RemoveMe",
        }));
        Assert.Contains("RECYCLED, not purged", remove);
        Assert.Contains("recycled", remove);

        // vault_list_staged no longer shows it, and neither does the promotion manifest.
        var list = Text(await client.CallToolAsync("vault_list_staged", new Dictionary<string, object?>()));
        Assert.DoesNotContain("Inbox/RemoveMe", list);
        var pending = PendingRequest.TryLoad(harness.Paths);
        Assert.NotNull(pending);
        Assert.DoesNotContain(pending.Entries, e => e.Path == "Inbox/RemoveMe");

        // Provenance record dropped.
        Assert.DoesNotContain(ProvenanceStore.Load(harness.Paths).Records, r => r.Path == "Inbox/RemoveMe");

        // The recycle-bin claim, proven RAW: keepassxc-cli search still matches the entry
        // under a Recycle Bin path (a raw ls would not show it — that is the filter's job).
        var search = await harness.Cli.SearchAsync(harness.StagingPath, VaultHarness.StagingPassword, null, "RemoveMe");
        Assert.True(search.Success, search.FailureSummary);
        Assert.Contains("Recycle Bin", search.StdOut);
        Assert.Contains("RemoveMe", search.StdOut);
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
        Assert.Contains("Error", reply);
        Assert.Contains("confirmation does not match", reply);

        Assert.Contains("Inbox/KeepMe", await harness.StagedEntryPathsAsync());
        Assert.Contains(ProvenanceStore.Load(harness.Paths).Records, r => r.Path == "Inbox/KeepMe");
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
        Assert.Contains("Error", reply);
        Assert.Contains("is not in staging", reply);
        Assert.Contains("Inbox/RealEntry", reply); // the current staged listing comes with the error

        Assert.Contains("Inbox/RealEntry", await harness.StagedEntryPathsAsync()); // nothing changed
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
        Assert.Contains("RECYCLED", remove);
        Assert.Empty(ProvenanceStore.Load(harness.Paths).Records);

        var restage = Text(await client.CallToolAsync("vault_stage_value", new Dictionary<string, object?>
        {
            ["label"] = "Inbox/ReStaged",
            ["value"] = "second-value-bbb",
        }));
        Assert.Contains("Staged into sandbox", restage);

        // One fresh record for the new value — no stale fingerprint, no retired leftovers.
        var rec = Assert.Single(ProvenanceStore.Load(harness.Paths).Records);
        Assert.Equal("Inbox/ReStaged", rec.Path);
        Assert.Equal(Origin.SeenByModel, rec.Origin);
        Assert.Empty(rec.RetiredFingerprints);
        Assert.NotEqual(Hashing.Sha256Hex("first-value-aaa"), rec.FingerprintSha256);
        Assert.Equal(Hashing.Sha256Hex("second-value-bbb"), rec.FingerprintSha256);
    }
}
