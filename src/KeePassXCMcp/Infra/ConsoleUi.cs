using Spectre.Console;
using Spectre.Console.Rendering;
using SpectreMarkup = Spectre.Console.Markup;

namespace KeePassXCMcp.Infra;

/// <summary>The single choke point for ALL human-facing console output (issue #24).
/// On a real interactive terminal it renders richly with the active theme; piped,
/// redirected, CI or NO_COLOR output is today's exact plain bytes — so every machine
/// consumer (the e2e suite, shells, logs) sees no difference, and MCP stdio mode never
/// touches this class at all (its stdout is JSON-RPC).
///
/// Surfaces express content + a semantic <see cref="Tone"/>; the theme decides colors
/// and whether sections become cards. Color, glyphs, boxes and hint lines are DECORATION:
/// they exist only on the rich path and never change the plain byte stream.</summary>
public sealed class ConsoleUi
{
    private readonly TextWriter _plain;
    private readonly IAnsiConsole? _ansi; // null == the plain fallback wins
    private readonly ConsoleTheme _theme;
    private List<IRenderable>? _collecting; // strata sections gather children, then draw one titled card

    public bool Rich => _ansi is not null;
    public ConsoleTheme Theme => _theme;

    private ConsoleUi(TextWriter plain, IAnsiConsole? ansi, ConsoleTheme theme)
    {
        _plain = plain;
        _ansi = ansi;
        _theme = theme;
    }

    // The live Console.Out/Error are fetched inside Create: if we decide to render richly
    // we first switch the process to UTF-8 output (box glyphs need real bytes), and .NET
    // hands out a NEW Console.Out after that switch — the plain path never takes it.
    public static ConsoleUi ForStdout(VaultConfig cfg) => Create(cfg, static () => Console.Out, Console.IsOutputRedirected, StdOutputHandle);
    public static ConsoleUi ForStderr(VaultConfig cfg) => Create(cfg, static () => Console.Error, Console.IsErrorRedirected, StdErrorHandle);

    /// <summary>Entry points for when no VaultConfig exists (config errors, the window
    /// launchers, usage): default theme on a real terminal, today's bytes on a pipe.</summary>
    public static ConsoleUi ForStdoutDefaultTheme() => Create(NoConfig, static () => Console.Out, Console.IsOutputRedirected, StdOutputHandle);
    public static ConsoleUi ForStderrDefaultTheme() => Create(NoConfig, static () => Console.Error, Console.IsErrorRedirected, StdErrorHandle);

    /// <summary>A config error happens before any config can be trusted — red text on a
    /// terminal, the exact message line elsewhere (never on MCP stdout).</summary>
    public static void ConfigError(string message) => ForStderrDefaultTheme().Line(message, Tone.Error);

    private static readonly VaultConfig NoConfig = new("", null, "", "", "");

    private static ConsoleUi Create(VaultConfig cfg, Func<TextWriter> liveWriter, bool redirected, int stdHandle)
    {
        var theme = Themes.Resolve(cfg.ConsoleTheme);
        if (!TerminalWantsRich(redirected))
            return new ConsoleUi(liveWriter(), null, theme);

        // Rich output draws box glyphs and rules; they must leave the process as real UTF-8
        // bytes (the default OEM/ANSI codepage writes '?' for them). This re-creates
        // Console.Out/Error, so the live writer is fetched only after the switch. The plain
        // path never gets here — its bytes stay exactly as they have always been.
        try { Console.OutputEncoding = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false); }
        catch { /* a console we may not own: glyphs degrade to '?', content is unaffected */ }

        // Windows: conhost parses SGR sequences only when the output buffer has
        // ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004) — Windows Terminal/ConPTY
        // pre-enable it, which hid the omission on modern hosts. Real console handles
        // only: a redirected handle fails the mode query, so forced-rich on a pipe
        // (the e2e hook) is a no-op.
        TryEnableVirtualTerminal();

        // And .NET's Console.Out feeds conhost encoded BYTES via WriteFile, which this
        // conhost stores verbatim — the Part C buffer dump showed real ESC cells and zero
        // parsing on one line while a WriteConsole write on the next line rendered. The
        // rich path therefore writes through WriteConsoleW to the real handle: that IS the
        // parsed path, and it is glyph-correct with no codepage involvement at all.
        // Non-console handles (pipes, CI, forced-rich e2e) keep plain Console.Out bytes.
        var writer = RichWriter(liveWriter, stdHandle);

        // We have decided this is a terminal; tell Spectre not to re-detect a pipe away from us.
        var settings = new AnsiConsoleSettings
        {
            Out = new AnsiConsoleOutput(writer),
            Ansi = AnsiSupport.Yes,
            ColorSystem = ColorSystemSupport.TrueColor,
        };
        IAnsiConsole ansi = AnsiConsole.Create(settings);
        ansi.Profile.Width = TerminalWidth(redirected);
        return new ConsoleUi(writer, ansi, theme);
    }

    /// <summary>Rich only on a real interactive terminal; NO_COLOR and CI always win.
    /// KEEPASSXC_MCP_RICH=1 forces rich rendering even on a pipe — the e2e hook for
    /// asserting the CONTENT of rich surfaces; it never affects any plain-path byte.</summary>
    private static bool TerminalWantsRich(bool redirected)
    {
        var force = Environment.GetEnvironmentVariable("KEEPASSXC_MCP_RICH");
        if (!string.IsNullOrEmpty(force))
            return force is "1" or "true" or "yes";
        return !redirected
               && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NO_COLOR"))
               && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI"));
    }

    private static int TerminalWidth(bool redirected)
    {
        var configured = Environment.GetEnvironmentVariable("KEEPASSXC_MCP_WIDTH");
        if (int.TryParse(configured, out var w) && w is >= 40 and <= 500) return w;
        if (!redirected)
        {
            try { if (Console.WindowWidth >= 40) return Console.WindowWidth; }
            catch { /* redirected after all — the width probe just failed */ }
        }
        return 400; // forced rich on a pipe: wide enough that content is never wrapped mid-assert
    }

    private static void TryEnableVirtualTerminal()
    {
        if (!OperatingSystem.IsWindows()) return;
        TryVt(StdOutputHandle);
        TryVt(StdErrorHandle);
    }

    private const int StdOutputHandle = -11, StdErrorHandle = -12; // STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
    // The OUTPUT-console flag is 0x0004. 0x0020 is an INPUT-only value that makes
    // SetConsoleMode reject the call outright (ERROR_INVALID_PARAMETER), and 0x0010 is
    // a valid-but-unrelated output flag — both shipped as bugs through the beta.1/beta.2
    // Part C drill before the console-buffer dump settled the mechanism.
    private const uint EnableVtProcessing = 0x0004;                 // ENABLE_VIRTUAL_TERMINAL_PROCESSING

    /// <summary>The rich writer for a real Windows console: strings go to the handle via
    /// WriteConsoleW — the input path conhost actually runs its VT parser on. Anything
    /// that is not a console handle (pipe, CI, forced-rich e2e) uses the live
    /// Console.Out/Error unchanged, so no machine-consumed byte ever changes.</summary>
    private static TextWriter RichWriter(Func<TextWriter> fallback, int stdHandle)
    {
        if (!OperatingSystem.IsWindows()) return fallback();
        var h = GetStdHandle(stdHandle);
        if (h == 0 || h == -1 || !GetConsoleMode(h, out _)) return fallback();
        return new DirectConsoleWriter(h, fallback());
    }

    private sealed class DirectConsoleWriter : TextWriter
    {
        private readonly nint _handle;
        private readonly TextWriter _fallback;

        internal DirectConsoleWriter(nint handle, TextWriter fallback)
        {
            _handle = handle;
            _fallback = fallback;
        }

        public override System.Text.Encoding Encoding => new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        public override void Write(char value) => WriteString(value.ToString());
        public override void Write(string? value) => WriteString(value);
        public override void WriteLine() => WriteString(NewLine);
        public override void WriteLine(string? value) => WriteString(value + NewLine);
        public override void Flush() { /* every write lands immediately */ }

        private void WriteString(string? s)
        {
            if (string.IsNullOrEmpty(s)) return;
            try
            {
                if (WriteConsoleW(_handle, s, (uint)s.Length, out _, IntPtr.Zero)) return;
            }
            catch { /* fall through to the ordinary stream */ }
            _fallback.Write(s); // content must never be lost — decoration is allowed to degrade
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern bool WriteConsoleW(nint hConsoleOutput, string lpBuffer,
            uint nNumberOfCharsToWrite, out uint lpNumberOfCharsWritten, IntPtr lpReserved);
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern nint GetStdHandle(int nStdHandle);
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool GetConsoleMode(nint hConsoleHandle, out uint lpMode);
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool SetConsoleMode(nint hConsoleHandle, uint dwMode);

    private static void TryVt(int stdHandle)
    {
        try
        {
            var h = GetStdHandle(stdHandle);
            if (h == 0 || h == -1) return;               // no handle / invalid
            if (!GetConsoleMode(h, out var mode)) return; // not a console (pipe / forced-rich)
            SetConsoleMode(h, mode | EnableVtProcessing);
        }
        catch { /* decoration never breaks a contract */ }
    }

    // ---------- content lines ----------

    /// <summary>A content line. Plain mode writes the text verbatim — color is
    /// decoration, never content, so these calls are byte-safe everywhere.</summary>
    public void Line(string text = "", Tone tone = Tone.Text)
    {
        if (_ansi is null)
        {
            _plain.WriteLine(text);
            return;
        }
        WriteLine(Tint(text, tone));
    }

    /// <summary>One line built from separately-toned spans (a banner where only one
    /// phrase is emphasized). Plain: the concatenated text, exact bytes.</summary>
    public void Segments(params (string Text, Tone Tone)[] parts)
    {
        if (_ansi is null)
        {
            _plain.Write(string.Concat(parts.Select(p => p.Text)));
            _plain.WriteLine();
            return;
        }
        WriteLine(string.Concat(parts.Select(p => Tint(p.Text, p.Tone))));
    }

    /// <summary>A key/value row in the status shape. Plain: exactly today's
    /// `key<padding>: value` bytes. Rich: muted key, tinted value — padding is a
    /// plain-alignment device, not something a themed terminal needs.</summary>
    public void Kv(string key, string value, int pad, Tone valueTone = Tone.Text)
    {
        if (_ansi is null)
        {
            var k = key.Length >= pad ? key : key.PadRight(pad);
            _plain.WriteLine($"{k}: {value}");
            return;
        }
        WriteLine($"{Tint(key, Tone.Muted)} {Tint(":", Tone.Faint)} {Tint(value, valueTone)}");
    }

    /// <summary>A list item under a count line (staged entries). Plain: the exact
    /// `  - item` bytes of today's output.</summary>
    public void Item(string text, Tone tone = Tone.Text)
    {
        if (_ansi is null)
        {
            _plain.WriteLine($"  - {text}");
            return;
        }
        WriteLine($"{Tint("•", Tone.Faint)} {Tint(text, tone)}");
    }

    // ---------- structure ----------

    /// <summary>A titled group of content. opencode: title + hairline rule; strata: a
    /// titled bordered card containing the section's rows; plain: writes nothing — the
    /// rows alone are today's whole output. Disposing closes the card.</summary>
    public SectionScope Section(string title) => new(this, title);

    public sealed class SectionScope : IDisposable
    {
        private readonly ConsoleUi _ui;
        private readonly string _title;
        private readonly List<IRenderable>? _children;

        internal SectionScope(ConsoleUi ui, string title)
        {
            _ui = ui;
            _title = title;
            if (ui._ansi is null) return;
            if (ui._theme.SectionsAsCards)
            {
                _children = [];
                ui._collecting = _children;
            }
            else
            {
                ui.WriteLine(ui.Tint(title, Tone.AccentStructural));
                ui.WriteLine(ui.Tint(new string('─', Math.Min(Math.Max(title.Length, 8), 72)), Tone.Border));
            }
        }

        public void Kv(string key, string value, int pad, Tone valueTone = Tone.Text) => _ui.Kv(key, value, pad, valueTone);
        public void Item(string text, Tone tone = Tone.Text) => _ui.Item(text, tone);
        public void Line(string text = "", Tone tone = Tone.Text) => _ui.Line(text, tone);
        public void Hint(string text) => _ui.Hint(text);

        public void Dispose()
        {
            if (_children is null) return;
            _ui._collecting = null;
            var panel = new Panel(new Rows(_children))
            {
                Header = new PanelHeader(_ui.Tint(_title, Tone.Accent)),
                Border = _ui._theme.CardBorder,
                Expand = false,
            };
            _ui.Write(panel);
        }
    }

    /// <summary>The merge dry-run. Plain: exactly today's bytes — one WriteLine of the
    /// lines joined with "\n" (not per-line newlines). Rich: read as a diff —
    /// additions and removals get +/- markers and color, so the approver sees exactly
    /// what will move before typing a password.</summary>
    public void Diff(IEnumerable<string> rawLines)
    {
        if (_ansi is null)
        {
            _plain.WriteLine(string.Join("\n", rawLines));
            return;
        }
        foreach (var line in rawLines)
        {
            var (marker, tone) = ClassifyDiff(line);
            WriteLine(Tint($"{marker}{line}", tone));
        }
    }

    private (string Marker, Tone Tone) ClassifyDiff(string line)
    {
        var t = line.TrimStart();
        if (t.StartsWith("Added", StringComparison.OrdinalIgnoreCase) ||
            t.StartsWith("Creating", StringComparison.OrdinalIgnoreCase) ||
            t.StartsWith("Created", StringComparison.OrdinalIgnoreCase))
            return ("+ ", Tone.Added);
        if (t.StartsWith("Removed", StringComparison.OrdinalIgnoreCase) ||
            t.StartsWith("Deleted", StringComparison.OrdinalIgnoreCase))
            return ("- ", Tone.Removed);
        if (t.Contains("Border", StringComparison.OrdinalIgnoreCase))
            return ("  ", Tone.AccentStructural); // keepassxc merge "Border" conflicts are structural, not +/-
        return ("  ", Tone.Muted);
    }

    /// <summary>The ONE bordered box of the opencode style: a decision step (confirm /
    /// password). Strata draws it as a card like everything else. Plain: a no-op — the
    /// surface still passes its exact prompt text to <see cref="ApproverConsole"/>, so
    /// the byte stream and the masked-read contract are untouched.</summary>
    public void PromptBox(string question, string hint = "")
    {
        if (_ansi is null) return;
        var items = new List<IRenderable> { new SpectreMarkup(Tint(question, Tone.Accent)) };
        if (hint.Length > 0) items.Add(new SpectreMarkup(Tint(hint, Tone.Faint)));
        var panel = new Panel(new Rows(items)) { Border = _theme.CardBorder, Expand = false };
        Write(panel);
    }

    /// <summary>A faint footer hint line (key hints, remedies). Rich only — plain
    /// output never grew hint lines, and plain stays byte-exact.</summary>
    public void Hint(string text)
    {
        if (_ansi is null) return;
        WriteLine(Tint(text, Tone.Faint));
    }

    /// <summary>An aligned table (audit records, the promote manifest). Rich only —
    /// the plain call sites keep writing their own today-verbatim lines.</summary>
    public void Table(string[] columns, IReadOnlyList<string[]> rows, IReadOnlyList<Tone>? rowTones = null)
    {
        if (_ansi is null) return;
        var table = new Table { Border = TableBorder.Square };
        foreach (var col in columns)
            table.AddColumn(new TableColumn(new SpectreMarkup(Tint(col, Tone.AccentStructural))) { NoWrap = true });
        for (var i = 0; i < rows.Count; i++)
        {
            var tone = rowTones is not null && i < rowTones.Count ? rowTones[i] : Tone.Text;
            table.AddRow(rows[i].Select(c => (IRenderable)new SpectreMarkup(Tint(c, tone))).ToArray());
        }
        Write(table);
    }

    // ---------- markup plumbing ----------

    /// <summary>Theme color over escaped content — values are never markup.</summary>
    private string Tint(string plain, Tone tone)
        => $"[{_theme.For(tone).ToMarkup()}]{SpectreMarkup.Escape(plain)}[/]";

    /// <summary>Line-level rich output: markup text rendered WITH its line terminator.
    /// (Spectre's bare Write(renderable) never ends a line — mixing those up joins the
    /// output.) Inside a strata card the markup line is collected instead, and the card
    /// renders as one block when the section closes.</summary>
    private void WriteLine(string markup)
    {
        if (_collecting is not null)
        {
            _collecting.Add(new SpectreMarkup(markup));
            return;
        }
        _ansi!.MarkupLine(markup);
    }

    /// <summary>Block-level rich output (panels, tables): they terminate themselves.</summary>
    private void Write(IRenderable renderable)
    {
        if (_collecting is not null) _collecting.Add(renderable);
        else _ansi!.Write(renderable);
    }
}
