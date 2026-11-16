namespace KeePassxcMcp.Infra;

/// <summary>Log/output redaction filter. Any message leaving this process for logs or
/// error text passes through here first; password-shaped values (known secrets) are
/// replaced. Belt-and-braces: the design never puts secrets into messages in the first place.</summary>
public static class Redact
{
    public static string Apply(string? message, IReadOnlyList<string> secrets)
    {
        if (string.IsNullOrEmpty(message)) return message ?? "";
        var result = message;
        foreach (var secret in secrets)
        {
            if (!string.IsNullOrEmpty(secret))
                result = result.Replace(secret, "[REDACTED]", StringComparison.Ordinal);
        }
        return result;
    }
}
