using System.Diagnostics;

namespace KeePassXCMcp.Infra;

/// <summary>
/// Opens `keepassxc-mcp promote` in a NEW interactive terminal window owned by the desktop
/// user. This is a launcher and nothing more: it pipes no data, feeds no keystrokes, and
/// starts a process that runs promote mode from scratch. The master password is typed by
/// the human into that OS console — neither this process nor any pipe it owns can see it.
/// When the OS has no visible-terminal mechanism (headless/CI), it says so and hands back
/// the manual command instead of pretending a window appeared.
/// </summary>
public static class ApproverLauncher
{
    public sealed record LaunchResult(bool Launched, string Method, string Detail);

    public static LaunchResult TryOpenPromoteWindow() => TryOpenWindow("promote");

    /// <summary>Reader window (SPEC.md E1). The only argument is the server pid — a plain
    /// integer for the orphan guard, never data, never a secret.</summary>
    public static LaunchResult TryOpenReaderWindow(int serverPid) => TryOpenWindow($"reader --server {serverPid}");

    private static LaunchResult TryOpenWindow(string args)
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
            return Manual(args, "could not determine this executable's own path");

        try
        {
            if (OperatingSystem.IsWindows())
                return OpenWindows(exe, args);
            if (OperatingSystem.IsMacOS())
                return OpenMacOS(exe, args);
            return OpenLinux(exe, args);
        }
        catch (Exception ex)
        {
            return Manual(args, ex.Message);
        }
    }

    private static LaunchResult OpenWindows(string exe, string args)
    {
        if (exe.Contains('"')) return Manual(args, $"executable path contains a quote: {exe}");
        // cmd /k keeps the window open after the mode exits so the outcome/exit code stays
        // readable. cmd quote-stripping: /k ""<exe>" promote" runs "<exe>" promote.
        var psi = new ProcessStartInfo("cmd.exe", $"/k \"\"{exe}\" {args}\"")
        {
            UseShellExecute = true, // console subsystem app → gets its own visible console window
        };
        Process.Start(psi);
        return new LaunchResult(true, "windows-console",
            $@"opened a new console window running: ""{exe}"" {args} (window stays open afterwards)");
    }

    private static LaunchResult OpenMacOS(string exe, string args)
    {
        if (exe.Contains('"')) return Manual(args, $"executable path contains a quote: {exe}");
        var psi = new ProcessStartInfo("/usr/bin/osascript") { UseShellExecute = false };
        psi.ArgumentList.Add("-e");
        psi.ArgumentList.Add($"tell application \"Terminal\" to do script \"\\\"{exe}\\\" {args}\"");
        psi.ArgumentList.Add("-e");
        psi.ArgumentList.Add("tell application \"Terminal\" to activate");
        Process.Start(psi);
        return new LaunchResult(true, "macos-Terminal",
            $"asked Terminal.app to run: \"{exe}\" {args} (its window stays open afterwards)");
    }

    private static LaunchResult OpenLinux(string exe, string args)
    {
        if (exe.Contains('\'')) return Manual(args, $"executable path contains a single quote: {exe}");
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DISPLAY")) &&
            string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WAYLAND_DISPLAY")))
            return Manual(args, "no DISPLAY/WAYLAND_DISPLAY — this looks like a headless session");

        // sh keeps the window useful after the command exits (result stays on screen until Enter).
        var shCmd = $"'{exe}' {args}; printf '\\n[keepassxc-mcp finished — press Enter to close this window]\\n'; read _";
        var candidates = new (string Bin, string[] Prefix)[]
        {
            ("gnome-terminal", ["--"]),
            ("konsole", ["-e"]),
            ("mate-terminal", ["--"]),
            ("x-terminal-emulator", ["-e"]),
            ("xterm", ["-e"]),
        };
        foreach (var (bin, prefix) in candidates)
        {
            var full = FindOnPath(bin);
            if (full is null) continue;
            var psi = new ProcessStartInfo(full) { UseShellExecute = false };
            foreach (var a in prefix) psi.ArgumentList.Add(a);
            psi.ArgumentList.Add("/bin/sh");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(shCmd);
            try
            {
                Process.Start(psi);
                return new LaunchResult(true, $"linux-{bin}", $"opened a terminal window running: {exe} {args}");
            }
            catch (Exception)
            {
                // candidate exists but refused to start — try the next one.
            }
        }
        return Manual(args, "no known terminal emulator (gnome-terminal/konsole/mate-terminal/x-terminal-emulator/xterm) is installed");
    }

    private static string? FindOnPath(string name)
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var full = Path.Combine(dir, name);
                if (File.Exists(full)) return full;
            }
            catch (ArgumentException) { }
        }
        return null;
    }

    private static LaunchResult Manual(string args, string reason) =>
        new(false, "none", $"{reason} — run \"keepassxc-mcp {args}\" in your own terminal instead.");
}
