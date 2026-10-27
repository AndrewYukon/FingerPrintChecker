using Xunit;

namespace FingerPrintChecker.Server.Tests;

public class BotHeadersTests
{
    private const string SigInput = "sig1=(\"@authority\" \"content-type\" \"X-Custom\" \"cookie\" \"signature-agent\");created=1;keyid=\"k\";tag=\"web-bot-auth\"";

    [Fact]
    public void KeepsAllowedSetAndDropsCookieAuthorization()
    {
        var allowed = new Dictionary<string, string>
        {
            ["User-Agent"] = "UA", ["Accept"] = "text/html", ["Accept-Language"] = "en", ["Accept-Encoding"] = "gzip",
            ["Sec-CH-UA"] = "\"x\"", ["Sec-CH-UA-Mobile"] = "?0", ["Sec-CH-UA-Platform"] = "\"macOS\"",
            ["Sec-Fetch-Site"] = "none", ["Sec-Fetch-Mode"] = "navigate", ["Sec-Fetch-Dest"] = "document", ["Sec-Fetch-User"] = "?1",
            ["Signature"] = "sig1=:a:", ["Signature-Input"] = "sig1=()", ["Signature-Agent"] = "\"https://chatgpt.com\"",
            ["Upgrade-Insecure-Requests"] = "1",
        };
        var all = new Dictionary<string, string>(allowed)
        {
            ["Cookie"] = "sid=1", ["Authorization"] = "Bearer x", ["X-Forwarded-For"] = "1.1.1.1",
        };
        var expected = allowed.ToDictionary(kv => kv.Key.ToLowerInvariant(), kv => kv.Value);
        Assert.Equal(expected, BotHeaders.Filter(all));
        Assert.Equal(15, BotHeaders.BotCheckHeaders.Count);
    }

    [Fact]
    public void RepeatedPairsAndCaseVariantsAreJoined()
    {
        var pairs = new List<KeyValuePair<string, string>> { new("Accept", "a"), new("accept", "b"), new("Cookie", "c") };
        Assert.Equal(new Dictionary<string, string> { ["accept"] = "a, b" }, BotHeaders.Filter(pairs));
        var dict = new Dictionary<string, string> { ["Accept"] = "a", ["ACCEPT"] = "b" };
        Assert.Equal("a, b", BotHeaders.Filter(dict)["accept"]);
    }

    [Fact]
    public void KeepsSignatureInputCoveredComponents()
    {
        var out1 = BotHeaders.Filter(new Dictionary<string, string>
        {
            ["Signature-Input"] = SigInput, ["Signature-Agent"] = "\"https://chatgpt.com\"", ["Content-Type"] = "text/plain",
            ["X-Custom"] = "v", ["X-Other"] = "no", ["Cookie"] = "sid=1", ["Authorization"] = "x", ["Proxy-Authorization"] = "p",
        });
        Assert.Equal("text/plain", out1["content-type"]);
        Assert.Equal("v", out1["x-custom"]);
        Assert.DoesNotContain("x-other", out1.Keys);
        Assert.DoesNotContain("cookie", out1.Keys);
        Assert.DoesNotContain("authorization", out1.Keys);
    }

    [Fact]
    public void ProxyAuthorizationNeverForwardedEvenWhenCovered()
    {
        var o = BotHeaders.Filter(new Dictionary<string, string>
        {
            ["signature-input"] = "sig1=(\"proxy-authorization\" \"authorization\" \"cookie\")", ["proxy-authorization"] = "p", ["authorization"] = "a", ["cookie"] = "c",
        });
        Assert.Equal(new[] { "signature-input" }, o.Keys.ToArray());
    }

    [Fact]
    public void NoExtrasWithoutSignatureInput()
    {
        var o = BotHeaders.Filter(new Dictionary<string, string> { ["content-type"] = "x", ["user-agent"] = "u" });
        Assert.Equal(new Dictionary<string, string> { ["user-agent"] = "u" }, o);
    }

    [Fact]
    public void CapsCoveredExtrasAt32()
    {
        var names = Enumerable.Range(0, 40).Select(i => $"x-h{i:00}").ToList();
        var h = names.ToDictionary(n => n, _ => "v");
        h["signature-input"] = "sig1=(" + string.Join(" ", names.Select(n => $"\"{n}\"")) + ")";
        var o = BotHeaders.Filter(h);
        Assert.Equal(32, o.Keys.Count(k => k.StartsWith("x-h", StringComparison.Ordinal)));
        Assert.Contains("x-h31", o.Keys);
        Assert.DoesNotContain("x-h32", o.Keys);
    }

    [Fact]
    public void NullGivesEmptyMap()
    {
        Assert.Empty(BotHeaders.Filter((IReadOnlyDictionary<string, string>?)null));
    }

    [Fact]
    public void BotCheckHeadersIsNotMutableThroughCast()
    {
        Assert.Throws<NotSupportedException>(() => ((ISet<string>)BotHeaders.BotCheckHeaders).Add("cookie"));
        Assert.DoesNotContain("cookie", BotHeaders.BotCheckHeaders);
    }
}
