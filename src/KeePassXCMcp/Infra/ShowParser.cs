using System.Globalization;
using System.Text.RegularExpressions;

namespace KeePassXCMcp.Infra;

public sealed record ParsedAttachment(string Name, long SizeBytes);

/// <summary>Parsed `keepassxc-cli show` output (default fields — which include Title,
/// UserName, URL, Notes, Uuid, Tags while Password prints as PROTECTED; plus attachments
/// when `--show-attachments` was used). Secret values are deliberately NOT modeled:
/// agent-facing reads must not carry them (SPEC.md F4).</summary>
public sealed record ShowOutput(string Title, string Notes, IReadOnlyList<ParsedAttachment> Attachments, string Uuid = "", string UserName = "", string Url = "");

public static partial class ShowParser
{
    [GeneratedRegex(@"^  (?<name>.+) \((?<size>[\d.]+) (?<unit>B|KiB|MiB|GiB|TiB)\)$")]
    private static partial Regex AttachmentLine();

    public static ShowOutput Parse(string showOutput)
    {
        var lines = showOutput.Replace("\r\n", "\n").Split('\n');
        string title = "", notes = "", uuid = "", userName = "", url = "";
        var attachments = new List<ParsedAttachment>();
        var inNotes = false;
        var inAttachments = false;

        foreach (var line in lines)
        {
            if (line.StartsWith("Title: ", StringComparison.Ordinal)) { title = line["Title: ".Length..]; continue; }
            if (line.StartsWith("Notes: ", StringComparison.Ordinal)) { notes = line["Notes: ".Length..]; inNotes = true; inAttachments = false; continue; }
            if (line.StartsWith("Attachments:", StringComparison.Ordinal)) { inNotes = false; inAttachments = true; continue; }
            // Field lines also terminate a multi-line notes block — same rule as before.
            if (line.StartsWith("Uuid: ", StringComparison.Ordinal)) { uuid = line["Uuid: ".Length..]; continue; }
            if (line.StartsWith("UserName: ", StringComparison.Ordinal)) { userName = line["UserName: ".Length..]; continue; }
            if (line.StartsWith("URL: ", StringComparison.Ordinal)) { url = line["URL: ".Length..]; continue; }
            if (line.StartsWith("Password: ", StringComparison.Ordinal)) { continue; }
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
        return new ShowOutput(title, notes.TrimEnd(), attachments, uuid, userName, url);
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
