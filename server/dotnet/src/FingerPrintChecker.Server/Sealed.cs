using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FingerPrintChecker.Server;

/// <summary>Decrypt the <c>sealedResult</c> blob returned by identify.</summary>
public static class Sealed
{
    private static readonly Regex B64 = new(@"\A[A-Za-z0-9+/]*={0,2}\z", RegexOptions.CultureInvariant);
    private static readonly byte[] Magic = "fps1"u8.ToArray();
    private const int MinLen = 4 + 4 + 12 + 16;
    private const int TagLen = 16;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Canonical standard base64 only: regex, length, decode, re-encode equality.</summary>
    private static byte[]? StrictB64(string? value)
    {
        if (value is null || value.Length % 4 != 0 || !B64.IsMatch(value))
        {
            return null;
        }

        var buffer = new byte[value.Length / 4 * 3];
        if (!Convert.TryFromBase64String(value, buffer, out var written))
        {
            return null;
        }

        var raw = buffer.AsSpan(0, written).ToArray();
        return Convert.ToBase64String(raw) == value ? raw : null;
    }

    /// <summary>
    /// Decrypt a sealed result. <paramref name="keys"/> are base64 32-byte project keys (pass the active and the
    /// previous one during rotation). Nothing partial is ever returned.
    /// </summary>
    /// <exception cref="SealedResultException">bad_format, unknown_key, decrypt_failed, invalid_key or unsupported_version.</exception>
    public static JsonElement UnsealResult(string blob, IEnumerable<string> keys)
    {
        if (keys is null)
        {
            throw new SealedResultException("invalid_key");
        }

        var keyBytes = new List<byte[]>();
        foreach (var k in keys)
        {
            var b = StrictB64(k);
            if (b is null || b.Length != 32)
            {
                throw new SealedResultException("invalid_key");
            }

            keyBytes.Add(b);
        }

        var raw = StrictB64(blob);
        if (raw is null || raw.Length < MinLen || !raw.AsSpan(0, 4).SequenceEqual(Magic))
        {
            throw new SealedResultException("bad_format");
        }

        var aad = raw.AsSpan(0, 8).ToArray();
        var keyId = raw.AsSpan(4, 4);
        var candidates = keyBytes.Where(k => SHA256.HashData(k).AsSpan(0, 4).SequenceEqual(keyId)).ToList();
        if (candidates.Count == 0)
        {
            throw new SealedResultException("unknown_key");
        }

        var nonce = raw.AsSpan(8, 12);
        var tag = raw.AsSpan(raw.Length - TagLen, TagLen);
        var cipher = raw.AsSpan(20, raw.Length - 20 - TagLen);
        byte[]? plain = null;
        foreach (var key in candidates)
        {
            var buf = new byte[cipher.Length];
            try
            {
                using var gcm = new AesGcm(key, TagLen);
                gcm.Decrypt(nonce, cipher, tag, buf, aad);
                plain = buf;
                break;
            }
            catch (CryptographicException)
            {
            }
        }

        if (plain is null)
        {
            throw new SealedResultException("decrypt_failed");
        }

        return ParsePayload(plain);
    }

    private static JsonElement ParsePayload(byte[] plain)
    {
        JsonElement root;
        try
        {
            StrictUtf8.GetString(plain);
            if (plain.Length >= 3 && plain[0] == 0xEF && plain[1] == 0xBB && plain[2] == 0xBF)
            {
                throw new JsonException("BOM");
            }

            using var doc = JsonDocument.Parse(plain, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
            root = doc.RootElement.Clone();
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException)
        {
            throw new SealedResultException("decrypt_failed");
        }

        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new SealedResultException("decrypt_failed");
        }

        if (!root.TryGetProperty("version", out var version)
            || version.ValueKind != JsonValueKind.Number
            || !version.TryGetDouble(out var v)
            || v != 1.0)
        {
            throw new SealedResultException("unsupported_version");
        }

        return root;
    }
}
