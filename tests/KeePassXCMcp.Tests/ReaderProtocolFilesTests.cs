using System.Diagnostics;
using System.Text;
using KeePassXCMcp.Infra;

namespace KeePassXCMcp.Tests;

/// <summary>Issue #23: the reader session travels through JSON files on disk
/// (session / command / result + their .tmp atomic-write leftovers). ReaderTests proves the
/// model never receives a secret value; this closes the raw-byte gap: after a real session,
/// every file in the config dir is scanned for the exact UTF-8 (and UTF-16) bytes of the
/// value — including a result file read straight off disk, mid-exchange. The control proves
/// the test vault is real and whole: raw keepassxc-cli finds every entry by search and
/// prints the value with `show -q`; the protocol files show neither.</summary>
public class ReaderProtocolFilesTests
{
    private static Process StartReader(VaultHarness h)
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
        psi.ArgumentList.Add("reader");
        psi.Environment["KEEPASSXC_MCP_CONFIG"] = h.Paths.ConfigFile;
        return Process.Start(psi)!;
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i + needle.Length <= haystack.Length; i++)
        {
            var hit = true;
            for (var j = 0; j < needle.Length; j++)
                if (haystack[i + j] != needle[j]) { hit = false; break; }
            if (hit) return true;
        }
        return false;
    }

    /// <summary>The raw-bytes assertion: no file in the config dir contains the secret value
    /// in any plausible encoding. Scanning the whole dir (not just the three protocol files)
    /// is deliberate: any stray copy — a .tmp leftover, an error echo written by a future
    /// refactor — lands in the same net.</summary>
    private static void AssertNoSecretBytes(ConfigPaths paths, string secret)
    {
        var utf8 = Encoding.UTF8.GetBytes(secret);
        var utf16 = Encoding.Unicode.GetBytes(secret);
        foreach (var file in Directory.GetFiles(paths.Dir))
        {
            var bytes = File.ReadAllBytes(file);
            var name = Path.GetFileName(file);
            Assert.False(ContainsSequence(bytes, utf8), $"{name} contains the secret value (UTF-8)");
            Assert.False(ContainsSequence(bytes, utf16), $"{name} contains the secret value (UTF-16)");
        }
    }

    [RequiresCliFact]
    public async Task ReaderProtocolFiles_NeverContainSecrets()
    {
        using var h = await VaultHarness.CreateAsync();
        const string secret = "protocol-file-bytes-77";

        // Three entries sharing one value — one byte leaking through any file is enough.
        await h.Cli.EnsureGroupAsync(h.MainPath, VaultHarness.MainPassword, null, "Inbox");
        foreach (var name in new[] { "SecretAlpha", "SecretBeta", "SecretGamma" })
        {
            var add = await h.Cli.AddWithValueAsync(h.MainPath, VaultHarness.MainPassword, null,
                $"Inbox/{name}", new Secret(secret), "shared-value probe", null, null);
            Assert.True(add.Success, add.FailureSummary);
        }

        // Control (raw binary sees the whole flow): search finds every entry by path, and
        // `show -q` prints the value itself — so the protocol-file absence below is the
        // protocol's doing, not an empty vault.
        var rawSearch = await h.Cli.SearchAsync(h.MainPath, VaultHarness.MainPassword, null, "Secret");
        Assert.True(rawSearch.Success, rawSearch.FailureSummary);
        rawSearch.StdOut.Should().Contain("Inbox/SecretAlpha").And.Contain("Inbox/SecretBeta").And.Contain("Inbox/SecretGamma");
        var rawValue = await h.Cli.ReadAttributeAsync(h.MainPath, VaultHarness.MainPassword, null, "Inbox/SecretBeta", "Password");
        rawValue.Should().Be(secret);

        // Real reader session, driven over the exact file protocol the tools use.
        using var proc = StartReader(h);
        var stdoutTask = proc.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        proc.StandardInput.WriteLine(VaultHarness.MainPassword);
        proc.StandardInput.Close();

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (!ReaderProtocol.TryGetLiveSession(h.Paths, out _) && DateTime.UtcNow < deadline)
            await Task.Delay(200, TestContext.Current.CancellationToken);
        Assert.True(ReaderProtocol.TryGetLiveSession(h.Paths, out _), "reader session never opened");

        var search = await ReaderClient.SendAsync(h.Paths, "search", "Secret", TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        Assert.True(search.Ok, search.Error);
        search.Output.Should().Contain("Inbox/SecretAlpha").And.NotContain(secret);
        AssertNoSecretBytes(h.Paths, secret); // mid-session: session + command files on disk

        // One exchange performed RAW, so the result file's own bytes can be inspected while
        // it is still on disk (ReaderClient deletes it the moment it parses).
        ReaderProtocol.WriteAtomic(h.Paths.ReaderCommandFile, new ReaderCommand { Id = "raw-bytes-probe", Op = "get", Arg = "Inbox/SecretBeta" });
        deadline = DateTime.UtcNow + TimeSpan.FromSeconds(60);
        while (!File.Exists(h.Paths.ReaderResultFile) && DateTime.UtcNow < deadline)
            await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.True(File.Exists(h.Paths.ReaderResultFile), "raw protocol exchange timed out");
        var onDisk = await File.ReadAllBytesAsync(h.Paths.ReaderResultFile, TestContext.Current.CancellationToken);
        var raw = ReaderProtocol.TryReadAtomic<ReaderResult>(h.Paths.ReaderResultFile);
        Assert.NotNull(raw);
        Assert.True(raw.Ok, raw.Error);
        raw.Output.Should().Contain("Title: SecretBeta")      // the protocol really fetched the entry…
            .And.Contain("Password: PROTECTED");              // …masked — and the file bytes…
        Assert.False(ContainsSequence(onDisk, Encoding.UTF8.GetBytes(secret)), "the on-disk result file held the value"); // …never did.
        File.Delete(h.Paths.ReaderResultFile);

        var close = await ReaderClient.SendAsync(h.Paths, "close", "", TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        Assert.True(close.Ok, close.Error);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);
        proc.ExitCode.Should().Be(0);
        _ = await stdoutTask;

        // After teardown: nothing left behind in any encoding.
        File.Exists(h.Paths.ReaderSessionFile).Should().BeFalse();
        AssertNoSecretBytes(h.Paths, secret);
    }
}
