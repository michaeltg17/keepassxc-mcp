namespace KeePassXCMcp.Infra;

/// <summary>A secret entry value, valid by construction (parse, don't validate): non-empty
/// and single-line, because the value travels to keepassxc-cli via the stdin line protocol.
///
/// Deliberately NOT a record — records auto-generate a ToString that prints every field,
/// which would leak the value into any log or debug dump. This type has nowhere to print
/// one: ToString is redacted. Reveal() is the single place a Secret becomes a plain
/// string again (the stdin/CLI boundary), so "where do secret strings exist in this
/// process?" is one grep for Reveal() and nothing else.
///
/// Scope: entry values on the F1–F3/F10 flows only. Vault/staging passwords have a
/// different lifecycle and trust role (SPEC/SECURITY), so they stay config strings.</summary>
public sealed class Secret
{
    private readonly string _value;

    public Secret(string value)
    {
        if (string.IsNullOrEmpty(value))
            throw new ArgumentException("the secret value must not be empty.");
        if (value.Contains('\r') || value.Contains('\n'))
            throw new ArgumentException("the secret value must be a single line (no newlines) — it travels via stdin line protocol.");
        _value = value;
    }

    public int Length => _value.Length;

    /// <summary>sha256 hex of the value — the non-reversible provenance fingerprint.</summary>
    public string FingerprintSha256 => Hashing.Sha256Hex(_value);

    /// <summary>The ONLY way the value leaves as a plain string: the stdin/CLI boundary.</summary>
    public string Reveal() => _value;

    public override string ToString() => $"Secret({Length} chars)";
}
