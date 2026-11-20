using KeePassxcMcp.Infra;

namespace KeePassxcMcp.Tests;

/// <summary>Locates keepassxc-cli (env KEEPASSXC_CLI, PATH, then common install paths).
/// When it is unavailable the whole integration suite skips — the plan's prereq gate.</summary>
public static class CliProbe
{
    private static readonly Lazy<string?> Cached = new(() =>
    {
        var candidates = new List<string>();
        var fromEnv = Environment.GetEnvironmentVariable("KEEPASSXC_CLI");
        if (!string.IsNullOrWhiteSpace(fromEnv)) candidates.Add(fromEnv!);
        candidates.Add("keepassxc-cli");
        if (OperatingSystem.IsWindows()) candidates.Add(@"C:\Program Files\KeePassXC\keepassxc-cli.exe");
        if (OperatingSystem.IsMacOS())
        {
            candidates.Add("/opt/homebrew/bin/keepassxc-cli");
            candidates.Add("/usr/local/bin/keepassxc-cli");
        }
        foreach (var candidate in candidates)
        {
            try
            {
                var result = new KeePassCli(candidate).RunAsync(["--version"]).GetAwaiter().GetResult();
                if (result.Success) return candidate;
            }
            catch (Exception)
            {
                // candidate missing; try the next one
            }
        }
        return null;
    });

    public static string? PathOrNull => Cached.Value;
    public static string Path => Cached.Value ?? throw new InvalidOperationException("keepassxc-cli unavailable");
}

/// <summary>Skips (rather than fails) when keepassxc-cli is not installed.</summary>
public sealed class RequiresCliFactAttribute : FactAttribute
{
    public RequiresCliFactAttribute(
        [System.Runtime.CompilerServices.CallerFilePath] string? sourceFilePath = null,
        [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber)
    {
        if (CliProbe.PathOrNull is null)
            Skip = "keepassxc-cli not available (install KeePassXC or set KEEPASSXC_CLI)";
    }
}

public sealed class RequiresCliTheoryAttribute : TheoryAttribute
{
    public RequiresCliTheoryAttribute(
        [System.Runtime.CompilerServices.CallerFilePath] string? sourceFilePath = null,
        [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber)
    {
        if (CliProbe.PathOrNull is null)
            Skip = "keepassxc-cli not available (install KeePassXC or set KEEPASSXC_CLI)";
    }
}
