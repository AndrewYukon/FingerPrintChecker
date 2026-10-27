using System.Collections.Frozen;
using System.Text.RegularExpressions;

namespace FingerPrintChecker.Server;

/// <summary>
/// The forwardable header map for <c>BotCheckAsync</c>, which applies <see cref="Filter(IReadOnlyDictionary{string, string})"/>
/// itself so Cookie and Authorization never leave your process.
/// </summary>
public static class BotHeaders
{
    /// <summary>The only request headers the bot check needs. Never Cookie or Authorization.</summary>
    public static readonly IReadOnlySet<string> BotCheckHeaders = new[]
    {
        "user-agent", "accept", "accept-language", "accept-encoding",
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
        "signature", "signature-input", "signature-agent", "upgrade-insecure-requests",
    }.ToFrozenSet();

    /// <summary>Never forwarded, even when a signature covers them: they carry credentials.</summary>
    private static readonly FrozenSet<string> NeverForward = new[] { "cookie", "authorization", "proxy-authorization" }.ToFrozenSet();

    private const int MaxExtra = 32;
    private static readonly Regex ParenList = new(@"\(([^)]*)\)", RegexOptions.CultureInvariant);
    private static readonly Regex Quoted = new("\"([^\"]*)\"", RegexOptions.CultureInvariant);

    private static List<string> CoveredHeaders(string signatureInput)
    {
        var names = new List<string>();
        foreach (Match list in ParenList.Matches(signatureInput))
        {
            foreach (Match q in Quoted.Matches(list.Groups[1].Value))
            {
                var n = q.Groups[1].Value.ToLowerInvariant();
                if (n.Length > 0 && !n.StartsWith('@'))
                {
                    names.Add(n);
                }
            }
        }

        return names;
    }

    /// <summary>
    /// Keep the allowed headers plus any header named as a covered component in the request's <c>signature-input</c>
    /// (so a signed request can be verified), with lower-cased names. Drops everything else; Cookie, Authorization and
    /// Proxy-Authorization are never forwarded. Names differing only by case are joined with ", ". Null gives an empty map.
    /// </summary>
    public static Dictionary<string, string> Filter(IReadOnlyDictionary<string, string>? headers) =>
        Filter((IEnumerable<KeyValuePair<string, string>>?)headers);

    /// <summary>Same, for header collections that can repeat a name (a list of pairs).</summary>
    public static Dictionary<string, string> Filter(IEnumerable<KeyValuePair<string, string>>? headers)
    {
        var every = new Dictionary<string, string>();
        if (headers is not null)
        {
            foreach (var (name, value) in headers)
            {
                if (name is null || value is null)
                {
                    continue;
                }

                var key = name.ToLowerInvariant();
                every[key] = every.TryGetValue(key, out var prev) ? prev + ", " + value : value;
            }
        }

        var wanted = new HashSet<string>(BotCheckHeaders);
        every.TryGetValue("signature-input", out var sigInput);
        foreach (var n in CoveredHeaders(sigInput ?? string.Empty).Where(n => !NeverForward.Contains(n)).Take(MaxExtra))
        {
            wanted.Add(n);
        }

        var result = new Dictionary<string, string>();
        foreach (var (k, v) in every)
        {
            if (wanted.Contains(k))
            {
                result[k] = v;
            }
        }

        return result;
    }
}
