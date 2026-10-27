using System.Security.Cryptography;
using System.Text;

namespace FingerPrintChecker.Server;

/// <summary>Verify the <c>FPC-Signature</c> header on webhook deliveries.</summary>
public static class Webhook
{
    private static bool IsWs(char c) => c is ' ' or '\t' or '\r' or '\n';

    private static bool IsHex64(string s)
    {
        if (s.Length != 64)
        {
            return false;
        }

        foreach (var c in s)
        {
            if (!(c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F'))
            {
                return false;
            }
        }

        return true;
    }

    private static (string TRaw, long T, List<string> V1) ParseHeader(string? header)
    {
        if (header is null || header.Any(IsWs))
        {
            throw new WebhookSignatureException("malformed_header");
        }

        string? t = null;
        var v1 = new List<string>();
        foreach (var part in header.Split(','))
        {
            var eq = part.IndexOf('=');
            if (part.Length == 0 || eq < 0)
            {
                throw new WebhookSignatureException("malformed_header");
            }

            var key = part[..eq];
            var value = part[(eq + 1)..];
            if (key == "t")
            {
                if (t is not null)
                {
                    throw new WebhookSignatureException("malformed_header");
                }

                t = value;
            }
            else if (key == "v1")
            {
                v1.Add(value);
            }
        }

        if (t is null || t.Length is < 1 or > 12 || !t.All(c => c is >= '0' and <= '9') || v1.Count == 0)
        {
            throw new WebhookSignatureException("malformed_header");
        }

        return (t, long.Parse(t, System.Globalization.CultureInfo.InvariantCulture), v1);
    }

    /// <summary>Convenience overload: the string is encoded as UTF-8 (a lone surrogate becomes U+FFFD).</summary>
    public static void VerifyWebhookSignature(string rawBody, string header, string secret, double toleranceSec = 300, double? now = null)
    {
        ArgumentNullException.ThrowIfNull(rawBody);
        VerifyWebhookSignature(Encoding.UTF8.GetBytes(rawBody), header, secret, toleranceSec, now);
    }

    /// <summary>
    /// Return normally if <paramref name="header"/> is a valid, fresh signature of <paramref name="rawBody"/>, else throw
    /// <see cref="WebhookSignatureException"/>. <paramref name="rawBody"/> must be the exact bytes received.
    /// </summary>
    /// <exception cref="ArgumentException">toleranceSec or now is not finite, or toleranceSec is negative.</exception>
    public static void VerifyWebhookSignature(ReadOnlySpan<byte> rawBody, string header, string secret, double toleranceSec = 300, double? now = null)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (!double.IsFinite(toleranceSec) || toleranceSec < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(toleranceSec), "toleranceSec must be a finite number >= 0");
        }

        if (now is { } n && !double.IsFinite(n))
        {
            throw new ArgumentOutOfRangeException(nameof(now), "now must be a finite number");
        }

        var clock = now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
        var (tRaw, t, v1) = ParseHeader(header);

        var prefix = Encoding.ASCII.GetBytes(tRaw + ".");
        var message = new byte[prefix.Length + rawBody.Length];
        prefix.CopyTo(message, 0);
        rawBody.CopyTo(message.AsSpan(prefix.Length));
        var expected = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), message);

        var match = false;
        foreach (var candidate in v1)
        {
            if (IsHex64(candidate) && CryptographicOperations.FixedTimeEquals(Convert.FromHexString(candidate), expected))
            {
                match = true;
            }
        }

        if (!match)
        {
            throw new WebhookSignatureException("bad_signature");
        }

        if (clock - t > toleranceSec)
        {
            throw new WebhookSignatureException("expired");
        }

        if (t - clock > toleranceSec)
        {
            throw new WebhookSignatureException("future");
        }
    }
}
