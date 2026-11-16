using System.Globalization;
using System.Text.RegularExpressions;

namespace KeePassxcMcp.Infra;

public sealed record ParsedAttachment(string Name, long SizeBytes);

/// <summary>Parsed `keepassxc-cli show --show-attachments` output.</summary>
public sealed record ShowOutput(string Title, string Notes, IReadOnlyList<ParsedAttachment> Attachments);

public static partial class ShowParser
{
    [GeneratedRegex(@"^  (?<name>.+) \((?<size>[\d.]+) (?<unit>B|KiB|MiB|GiB|TiB)\)$")]
    private static partial Regex AttachmentLine();

    public static ShowOutput Parse(string showOutput)
    {
        var lines = showOutput.Replace("\r\n", "\n").Split('\n');
        string title = "", notes = "";
        var attachments = new List<ParsedAttachment>();
        var inNotes = false;
        var inAttachments = false;

        foreach (var line in lines)
        {
            if (line.StartsWith("Title: ", StringComparison.Ordinal)) { title = line["Title: ".Length..]; continue; }
            if (line.StartsWith("Notes: ", StringComparison.Ordinal)) { notes = line["Notes: ".Length..]; inNotes = true; inAttachments = false; continue; }
            if (line.StartsWith("Attachments:", StringComparison.Ordinal)) { inNotes = false; inAttachments = true; continue; }
            // Any other line belongs to a multi-line notes block (may be indented).
            if (inNotes)
            {
                if (Regex.IsMatch(line, @"^(UserName|Password|URL|Uuid|Tags):")) { inNotes = false; continue; }
                notes += "\n" + line;
                continue;
            }
            if (inAttachments)
            {
                var m = AttachmentLine().Match(line);
                if (m.Success)
                    attachments.Add(new ParsedAttachment(m.Groups["name"].Value, ToBytes(m.Groups["size"].Value, m.Groups["unit"].Value)));
            }
        }
        return new ShowOutput(title, notes.TrimEnd(), attachments);
    }

    private static long ToBytes(string number, string unit)
    {
        var value = double.Parse(number, CultureInfo.InvariantCulture);
        return unit switch
        {
            "B" => (long)value,
            "KiB" => (long)(value * 1024),
            "MiB" => (long)(value * 1024 * 1024),
            "GiB" => (long)(value * 1024 * 1024 * 1024),
            "TiB" => (long)(value * 1024L * 1024 * 1024 * 1024),
            _ => throw new InvalidOperationException($"unknown size unit {unit}"),
        };
    }
}
