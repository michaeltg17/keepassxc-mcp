using System.Diagnostics;
using System.Runtime.InteropServices;

namespace KeePassxcMcp.Tests;

/// <summary>
/// Test hygiene for the real approver window that vault_open_approver opens: the window
/// stays open on purpose (cmd /k keeps the outcome readable for a HUMAN) — correct product
/// behavior, so it is closed HERE, never in product code.
/// The window is located through the real process chain (this test → MCP server child,
/// possibly nested behind the SDK's cmd wrapper → the window's cmd → its promote child),
/// and only processes whose parent chain traces back to this test process are touched —
/// other keepassxc-mcp processes on the machine (e.g. a live MCP connection) are never
/// candidates. Closing is polite (WM_CLOSE on the console window, like clicking its X):
/// the hosted cmd exits normally and Windows Terminal closes the tab itself; a raw Kill
/// would leave the terminal's "process exited" tab behind. Kill is the fallback only.
/// Windows-only: the macOS/Linux launchers have no such child tree.
/// </summary>
internal static class ApproverWindowCloser
{
    /// <summary>Finds the window opened by a server process started by THIS test and closes
    /// it. Best-effort by design: the caller's assertions already stand; this must never
    /// change a verdict.</summary>
    internal static async Task CloseOpenedWindowAsync(string serverExePath, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return;
        var serverName = Path.GetFileNameWithoutExtension(serverExePath);
        for (var attempt = 0; attempt < 10; attempt++) // the window takes a moment to appear
        {
            var parentOf = SnapshotParentPids();
            var ourServerPids = Process.GetProcessesByName(serverName)
                .Select(p => p.Id)
                .Where(id => TracesToThisProcess(id, parentOf))
                .ToHashSet();
            foreach (var window in Process.GetProcessesByName("cmd").Select(p => p.Id)
                         .Where(id => ourServerPids.Contains(parentOf.GetValueOrDefault(id))))
            {
                CloseConsoleGracefully(window);
                try
                {
                    using var w = Process.GetProcessById(window);
                    if (!w.WaitForExit(2000)) w.Kill(entireProcessTree: true); // fallback only
                    else w.WaitForExit(); // its children (promote) end with the console
                }
                catch (ArgumentException) { } // already gone
                catch (InvalidOperationException) { } // already gone
                return;
            }
            await Task.Delay(500, ct);
        }
        // Not found: nothing to clean up; the test's verdict is unaffected.
    }

    private static bool TracesToThisProcess(int pid, IReadOnlyDictionary<int, int> parentOf)
    {
        for (var hop = 0; hop < 8 && parentOf.TryGetValue(pid, out var parent); pid = parent)
            if (parent == Environment.ProcessId) return true;
        return false;
    }

    // Polite console teardown: WM_CLOSE on the console window behaves like clicking its X —
    // the hosted cmd exits normally and the terminal (Windows Terminal included) closes the
    // tab itself.
    private static void CloseConsoleGracefully(int processWithConsole)
    {
        FreeConsole(); // detach the test host from its own console for the duration
        try
        {
            if (AttachConsole((uint)processWithConsole))
            {
                try
                {
                    var hwnd = GetConsoleWindow();
                    if (hwnd != IntPtr.Zero) PostMessageW(hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                }
                finally { FreeConsole(); }
            }
        }
        catch { } // best-effort; the tree-kill fallback still stands
        finally
        {
            try { AttachConsole((uint)Environment.ProcessId); } catch { } // restore ours
        }
    }

    // pid -> parent pid, via the standard kernel32 process snapshot.
    private static Dictionary<int, int> SnapshotParentPids()
    {
        var map = new Dictionary<int, int>();
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap.ToInt64() is 0 or -1) return map;
        try
        {
            var entry = new ProcessEntry32 { DwSize = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snap, ref entry)) return map;
            do map[(int)entry.Th32ProcessId] = (int)entry.Th32ParentProcessId;
            while (Process32Next(snap, ref entry));
        }
        catch
        {
            // best-effort: an empty map just means "nothing to close this attempt"
        }
        finally { CloseHandle(snap); }
        return map;
    }

    private const uint WM_CLOSE = 0x0010;
    private const uint TH32CS_SNAPPROCESS = 0x2;

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AttachConsole(uint processId);
    [DllImport("kernel32.dll")] private static extern bool FreeConsole();
    [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] private static extern bool PostMessageW(IntPtr hwnd, uint msg, IntPtr wparam, IntPtr lparam);

    [DllImport("kernel32.dll")] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint DwSize;
        public uint CntUsage;
        public uint Th32ProcessId;
        public IntPtr Th32DefaultHeapId;
        public uint Th32ModuleId;
        public uint CntThreads;
        public uint Th32ParentProcessId;
        public int PcPriClassBase;
        public uint DwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExeFile;
    }
}
