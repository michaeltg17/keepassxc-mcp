using System.Diagnostics;
using KeePassXCMcp.Infra;

namespace KeePassXCMcp.Tests;

/// <summary>The promote identity banner: whatever opened the window (human or
/// vault_open_approver), the banner tells the human which binary — path, version,
/// sha256 — is about to prompt for the master password. (vault_open_approver's own
/// behavior is covered over stdio in McpE2ETests.)</summary>
public class ApproverWindowTests
{
    [Fact]
    public async Task Promote_BannerIdentifiesItsOwnExecutable()
    {
        var dir = Path.Combine(Path.GetTempPath(), "kpxc-mcp-apw-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var configFile = Path.Combine(dir, "config.json");
        File.WriteAllText(configFile, """
            { "mainVaultPath": "unused.kdbx", "stagingVaultPath": "unused-staging.kdbx",
              "stagingPassword": "unused", "keepassxcCliPath": "keepassxc-cli" }
            """);
        try
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
            psi.ArgumentList.Add("promote");
            psi.Environment["KEEPASSXC_MCP_CONFIG"] = configFile;

            // given: a config pointing at unused vaults — there will be NO pending
            // request, so promote must refuse…
            using var proc = Process.Start(psi)!;
            proc.StandardInput.Close();
            var stderr = await proc.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
            await proc.WaitForExitAsync(TestContext.Current.CancellationToken);

            // …but the identity banner prints first, whatever happens: path, version and
            // sha256 of the exact binary that would ask for the master password — so a
            // human at the window always knows what they are authenticating.
            proc.ExitCode.Should().Be((int)Promoter.Exit.Error);
            stderr.Should().Contain(VaultHarness.ServerExePath)
                .And.Contain($"(v{AppInfo.Version})")
                .And.MatchRegex(@"its sha256\s*: [0-9a-f]{64}");
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}
