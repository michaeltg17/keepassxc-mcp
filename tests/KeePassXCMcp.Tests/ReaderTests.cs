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
        using var h = await VaultHarness.CreateAsync();
        const string secret = "reader-entry-secret-42";
        await h.Cli.EnsureGroupAsync(h.MainPath, VaultHarness.MainPassword, null, "Inbox");
        var add = await h.Cli.AddWithValueAsync(h.MainPath, VaultHarness.MainPassword, null,
            "Inbox/ReaderEntry", secret, "reader notes", "svc-user", "https://example.test");
        Assert.True(add.Success, add.FailureSummary);

        using var proc = StartReader(h);
        var stderrTask = proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        var stdoutTask = proc.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        proc.StandardInput.WriteLine(VaultHarness.MainPassword);
        proc.StandardInput.Close();

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (!ReaderProtocol.TryGetLiveSession(h.Paths, out _) && DateTime.UtcNow < deadline)
            await Task.Delay(200, TestContext.Current.CancellationToken);
        Assert.True(ReaderProtocol.TryGetLiveSession(h.Paths, out var session), "reader session never opened");
        Assert.Equal(proc.Id, session.Pid);

        // search: paths only
        var search = await ReaderClient.SendAsync(h.Paths, "search", "Reader", TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        Assert.True(search.Ok, search.Error);
        Assert.Contains("Inbox/ReaderEntry", search.Output);
        Assert.DoesNotContain(secret, search.Output);

        // get: metadata yes, value no — and the CLI-level mask is visible end-to-end
        var get = await ReaderClient.SendAsync(h.Paths, "get", "Inbox/ReaderEntry", TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        Assert.True(get.Ok, get.Error);
        Assert.Contains("Title: ReaderEntry", get.Output);
        Assert.Contains("UserName: svc-user", get.Output);
        Assert.Contains("reader notes", get.Output);
        Assert.Contains("Password: PROTECTED", get.Output);
        Assert.DoesNotContain(secret, get.Output);

        // get on a missing entry: clean error result, reader survives
        var missing = await ReaderClient.SendAsync(h.Paths, "get", "Inbox/Nope", TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        Assert.False(missing.Ok);
        var stillAlive = await ReaderClient.SendAsync(h.Paths, "search", "Reader", TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        Assert.True(stillAlive.Ok, stillAlive.Error);

        var close = await ReaderClient.SendAsync(h.Paths, "close", "", TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        Assert.True(close.Ok, close.Error);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, proc.ExitCode);
        Assert.False(File.Exists(h.Paths.ReaderSessionFile));
        Assert.Contains("Closed by request", await stderrTask);
        _ = await stdoutTask;
    }

    [RequiresCliFact]
    public async Task Reader_WrongPassword_InputClosed_ExitsOne_NoSession()
    {
        using var h = await VaultHarness.CreateAsync();
        using var proc = StartReader(h);
        var stderrTask = proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        proc.StandardInput.WriteLine("totally-wrong-password");
        proc.StandardInput.Close();
        var stderr = await stderrTask;
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1, proc.ExitCode);
        Assert.Contains("Attempt failed", stderr);
        Assert.Contains("Input closed at the password prompt", stderr);
        Assert.False(ReaderProtocol.TryGetLiveSession(h.Paths, out _));
        Assert.False(File.Exists(h.Paths.ReaderSessionFile));
    }

    [RequiresCliFact]
    public async Task Reader_OrphanGuard_ExitsWhenServerPidGone()
    {
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
        psi.ArgumentList.Add("999999"); // a pid that almost certainly does not exist
        psi.Environment["KEEPASSXC_MCP_CONFIG"] = h.Paths.ConfigFile;

        using var proc = Process.Start(psi)!;
        proc.StandardInput.WriteLine(VaultHarness.MainPassword);
        proc.StandardInput.Close();
        var stderr = await proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await proc.WaitForExitAsync(TestContext.Current.CancellationToken); // orphan guard closes it

        Assert.Equal(0, proc.ExitCode);
        Assert.Contains("orphan guard", stderr);
        Assert.False(File.Exists(h.Paths.ReaderSessionFile));
    }
}
