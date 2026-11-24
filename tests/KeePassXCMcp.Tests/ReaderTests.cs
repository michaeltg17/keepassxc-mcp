using System.Diagnostics;
using KeePassXCMcp.Infra;

namespace KeePassXCMcp.Tests;

/// <summary>End-to-end reader session (SPEC.md E1): a real `reader` process with the
/// password fed through redirected stdin (the test analogue of typing in a terminal),
/// driven over the exact file protocol vault_search/vault_get use. Core assertion:
/// reads work AND the entry's secret value never appears in any result.</summary>
public class ReaderTests
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

    [RequiresCliFact]
    public async Task ReaderSession_Search_Get_Close_NeverLeaksValue()
    {
        // given: a main vault with one entry holding a secret value, and no reader yet
        using var h = await VaultHarness.CreateAsync();
        const string secret = "reader-entry-secret-42";
        await h.Cli.EnsureGroupAsync(h.MainPath, VaultHarness.MainPassword, null, "Inbox");
        var add = await h.Cli.AddWithValueAsync(h.MainPath, VaultHarness.MainPassword, null,
            "Inbox/ReaderEntry", new Secret(secret), "reader notes", "svc-user", "https://example.test");
        Assert.True(add.Success, add.FailureSummary);

        // and: a reader process unlocking the vault with the password typed once on stdin
        // (the test analogue of typing in the terminal window)
        using var proc = StartReader(h);
        var stderrTask = proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        var stdoutTask = proc.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        proc.StandardInput.WriteLine(VaultHarness.MainPassword);
        proc.StandardInput.Close();

        // when: the session comes up, its file advertises the live process
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (!ReaderProtocol.TryGetLiveSession(h.Paths, out _) && DateTime.UtcNow < deadline)
            await Task.Delay(200, TestContext.Current.CancellationToken);
        Assert.True(ReaderProtocol.TryGetLiveSession(h.Paths, out var session), "reader session never opened");
        session.Pid.Should().Be(proc.Id);

        // then: search lists paths only — never the value
        var search = await ReaderClient.SendAsync(h.Paths, "search", "Reader", TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        Assert.True(search.Ok, search.Error);
        search.Output.Should().Contain("Inbox/ReaderEntry").And.NotContain(secret);

        // then: get returns metadata, masks the password (PROTECTED end-to-end), and never
        // puts the value anywhere in the output
        var get = await ReaderClient.SendAsync(h.Paths, "get", "Inbox/ReaderEntry", TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        Assert.True(get.Ok, get.Error);
        get.Output.Should().Contain("Title: ReaderEntry").And.Contain("UserName: svc-user")
            .And.Contain("reader notes").And.Contain("Password: PROTECTED")
            .And.NotContain(secret);

        // when: get asks for a missing entry, then: a clean error result — and the session
        // stays alive for the next request
        var missing = await ReaderClient.SendAsync(h.Paths, "get", "Inbox/Nope", TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        missing.Ok.Should().BeFalse();
        var stillAlive = await ReaderClient.SendAsync(h.Paths, "search", "Reader", TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        Assert.True(stillAlive.Ok, stillAlive.Error);

        // when: close is requested, then: clean exit, session file removed, honest goodbye
        var close = await ReaderClient.SendAsync(h.Paths, "close", "", TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        Assert.True(close.Ok, close.Error);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);
        proc.ExitCode.Should().Be(0);
        File.Exists(h.Paths.ReaderSessionFile).Should().BeFalse();
        (await stderrTask).Should().Contain("Closed by request");
        _ = await stdoutTask;
    }

    [RequiresCliFact]
    public async Task Reader_WrongPassword_InputClosed_ExitsOne_NoSession()
    {
        // given: a reader waiting at the password prompt
        using var h = await VaultHarness.CreateAsync();
        using var proc = StartReader(h);
        var stderrTask = proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);

        // when: the only attempt is wrong and stdin closes (no second try possible)
        proc.StandardInput.WriteLine("totally-wrong-password");
        proc.StandardInput.Close();
        var stderr = await stderrTask;
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);

        // then: it fails honestly — exit 1, both messages on stderr, and NO session to use
        proc.ExitCode.Should().Be(1);
        stderr.Should().Contain("Attempt failed").And.Contain("Input closed at the password prompt");
        ReaderProtocol.TryGetLiveSession(h.Paths, out _).Should().BeFalse();
        File.Exists(h.Paths.ReaderSessionFile).Should().BeFalse();
    }

    [RequiresCliFact]
    public async Task Reader_OrphanGuard_ExitsWhenServerPidGone()
    {
        // given: a reader started with --server pointing at a pid that almost certainly
        // does not exist (no MCP server to serve)
        using var h = await VaultHarness.CreateAsync();
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
        psi.ArgumentList.Add("--server");
        psi.ArgumentList.Add("999999");
        psi.Environment["KEEPASSXC_MCP_CONFIG"] = h.Paths.ConfigFile;

        // when: the session unlocks successfully despite the dead server
        using var proc = Process.Start(psi)!;
        proc.StandardInput.WriteLine(VaultHarness.MainPassword);
        proc.StandardInput.Close();
        var stderr = await proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken); // orphan guard closes it

        // then: the guard closes it — clean exit, the reason on stderr, session file gone
        proc.ExitCode.Should().Be(0);
        stderr.Should().Contain("orphan guard");
        File.Exists(h.Paths.ReaderSessionFile).Should().BeFalse();
    }
}
