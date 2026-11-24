using Spectre.Console;

namespace KeePassXCMcp.Infra;

/// <summary>Semantic roles for human-facing console output — named after what a piece of
/// output MEANS, never after a color. Surfaces pick a role; the active theme decides the
/// color and whether sections are drawn as cards. Exactly two built-in themes exist
/// (see <see cref="Themes"/>); there are no custom palettes.</summary>
public enum Tone
{
    /// <summary>Primary content: paths, values, result text.</summary>
    Text,
    /// <summary>Keys, labels, secondary wording.</summary>
    Muted,
    /// <summary>Hints, footers, "you can safely ignore this" lines.</summary>
    Faint,
    /// <summary>Box borders and rules.</summary>
    Border,
    /// <summary>Interactive / emphasized: prompts, options, things you should act on.</summary>
    Accent,
    /// <summary>Structural markers: section titles, table headers, diff hunk context.</summary>
    AccentStructural,
    /// <summary>Diff additions.</summary>
    Added,
    /// <summary>Diff removals.</summary>
    Removed,
    /// <summary>Successful outcomes (✓).</summary>
    Success,
    /// <summary>Warnings that do not stop the flow (⚠).</summary>
    Warning,
    /// <summary>Errors and refusals (✗).</summary>
    Error,
}

/// <summary>A built-in console theme: one palette over the semantic roles, plus the two
/// layout flags that actually change structure (opencode is borderless with hairline
/// rules; strata draws titled bordered cards). Colors are given as hex so both themes
/// look the same across terminals; Spectre degrades them automatically on weak ones.</summary>
public sealed record ConsoleTheme(
    string Name,
    Color Text, Color Muted, Color Faint, Color Border,
    Color Accent, Color AccentStructural,
    Color Added, Color Removed, Color Success, Color Warning, Color Error,
    bool SectionsAsCards,
    BoxBorder CardBorder)
{
    public Color For(Tone tone) => tone switch
    {
        Tone.Text => Text,
        Tone.Muted => Muted,
        Tone.Faint => Faint,
        Tone.Border => Border,
        Tone.Accent => Accent,
        Tone.AccentStructural => AccentStructural,
        Tone.Added => Added,
        Tone.Removed => Removed,
        Tone.Success => Success,
        Tone.Warning => Warning,
        Tone.Error => Error,
        _ => Text,
    };
}

public static class Themes
{
    /// <summary>Default theme, and the fallback for an absent or unknown setting value.</summary>
    public const string DefaultName = "opencode";

    /// <summary>OpenCode-TUI style: mostly borderless sections separated by hairline
    /// rules, a strict grey hierarchy (near-white values / muted keys / faint hints),
    /// warm orange reserved for things the human acts on, purple for structural markers.
    /// Rounded panels appear only at decision steps.</summary>
    public static ConsoleTheme OpenCode { get; } = new(
        Name: "opencode",
        Text: Color.FromHex("#E4E4E4"), Muted: Color.FromHex("#A0A0A0"), Faint: Color.FromHex("#6A6A6A"),
        Border: Color.FromHex("#585858"),
        Accent: Color.FromHex("#D75F00"), AccentStructural: Color.FromHex("#AF5FD7"),
        Added: Color.FromHex("#5FD75F"), Removed: Color.FromHex("#D75F5F"),
        Success: Color.FromHex("#5FD75F"), Warning: Color.FromHex("#D7AF5F"), Error: Color.FromHex("#D75F5F"),
        SectionsAsCards: false,
        CardBorder: BoxBorder.Rounded);

    /// <summary>Strata terminal-monitor style (github.com/Niko1221/Strata): the same
    /// information as titled bordered card panels, green for healthy state / structural
    /// headers, amber for warnings, aligned stat rows with honest sub-labels.</summary>
    public static ConsoleTheme Strata { get; } = new(
        Name: "strata",
        Text: Color.FromHex("#D0D0D0"), Muted: Color.FromHex("#8A8A8A"), Faint: Color.FromHex("#6A6A6A"),
        Border: Color.FromHex("#767676"),
        Accent: Color.FromHex("#00D787"), AccentStructural: Color.FromHex("#00D787"),
        Added: Color.FromHex("#00D787"), Removed: Color.FromHex("#D75F5F"),
        Success: Color.FromHex("#00D787"), Warning: Color.FromHex("#FFAF5F"), Error: Color.FromHex("#D75F5F"),
        SectionsAsCards: true,
        CardBorder: BoxBorder.Square);

    /// <summary>The setting picks one of exactly two names; anything else (absent,
    /// unknown, misspelled) resolves to the default without an error.</summary>
    public static ConsoleTheme Resolve(string? name) =>
        string.Equals(name?.Trim(), "strata", StringComparison.OrdinalIgnoreCase) ? Strata : OpenCode;
}
