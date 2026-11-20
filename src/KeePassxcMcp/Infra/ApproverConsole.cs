using System.Text;

namespace KeePassxcMcp.Infra;

/// <summary>Terminal interaction for the human approver (`promote` mode).
/// Password is read with echo OFF via a masked Console.ReadKey loop.
/// When stdin is redirected (automation/tests only) it falls back to a plain line read —
/// masking is only meaningful — and only possible — in a real terminal.</summary>
public static class ApproverConsole
{
    public static bool Confirm(string prompt)
    {
        Console.Error.Write(prompt);
        var answer = Console.ReadLine();
        return answer is not null && answer.Trim().Equals("y", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Interactive gate: nothing proceeds in a real terminal until the human
    /// presses Enter there. Skipped when stdin is redirected (tests/automation only).</summary>
    public static void WaitEnter(string prompt)
    {
        if (Console.IsInputRedirected) return;
        Console.Error.Write(prompt);
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                return;
            }
        }
    }

    /// <summary>Reads a password; null when stdin is closed (EOF — automation/tests only,
    /// a real terminal ends interaction via Enter/Esc/Ctrl+C instead).</summary>
    public static string? ReadPassword(string prompt)
    {
        Console.Error.Write(prompt);
        if (Console.IsInputRedirected)
        {
            var line = Console.ReadLine();
            Console.Error.WriteLine();
            return line;
        }

        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            switch (key.Key)
            {
                case ConsoleKey.Enter:
                    Console.Error.WriteLine();
                    return sb.ToString();
                case ConsoleKey.Backspace:
                    if (sb.Length > 0)
                    {
                        sb.Length--;
                        Console.Error.Write("\b \b");
                    }
                    break;
                case ConsoleKey.Escape:
                    Console.Error.WriteLine();
                    return "";
                default:
                    if (!char.IsControl(key.KeyChar))
                    {
                        sb.Append(key.KeyChar);
                        Console.Error.Write('*');
                    }
                    break;
            }
        }
    }
}
