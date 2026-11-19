using System.Reflection;

namespace KeePassxcMcp.Infra;

/// <summary>Our own build identity — surfaced in `--version`, `status`, and the promote
/// identity banner, so humans (and agents) can check WHICH keepassxc-mcp is running
/// without eyeballing sha256s. Falls back to "dev" outside a versioned build.</summary>
public static class AppInfo
{
    public static string Version { get; } =
        (typeof(AppInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "dev")
        .Split('+')[0]; // strip any +<sourcerevision> metadata
}
