// Compile check for README.md: the "Verifying an eventId", "Bot check" and "Webhooks" snippets, logic unchanged.
// ASP.NET types (Request, Results, clientIp) are replaced by the plain stand-ins at the bottom.
// The usings below are the README's own; ImplicitUsings (System, System.IO, System.Linq, ...) also apply in a real web project.
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using FingerPrintChecker.Server;
using Xunit;

namespace FingerPrintChecker.Server.Tests;

public interface IUsedEvents
{
    bool MarkUsed(string eventId);
}

public class ReadmeSnippets
{
    public static async Task<JsonElement> VerifyEventAsync(FpChecker fp, string eventId, IUsedEvents used)
    {
        // 1. Shape: ev_ followed by 20 Crockford base32 characters.
        if (!Regex.IsMatch(eventId, @"\Aev_[0-9A-HJKMNP-TV-Z]{20}\z"))
        {
            throw new InvalidOperationException("bad event id");
        }

        var ev = await fp.GetEventAsync(eventId);

        // 2. The event the server returns must be the one you asked for.
        if (!ev.TryGetProperty("eventId", out var id) || id.GetString() != eventId)
        {
            throw new InvalidOperationException("event id mismatch");
        }

        // 3. Fresh: created within the last 5 minutes. An unreadable createdAt fails closed.
        if (!ev.TryGetProperty("createdAt", out var c)
            || c.ValueKind != JsonValueKind.String
            || !DateTimeOffset.TryParse(c.GetString(), CultureInfo.InvariantCulture,
                   DateTimeStyles.RoundtripKind | DateTimeStyles.AssumeUniversal, out var created)
            || Math.Abs((DateTimeOffset.UtcNow - created).TotalSeconds) > 300)
        {
            throw new InvalidOperationException("event too old or unreadable");
        }

        // 4. Single use: an event id is accepted once.
        if (!used.MarkUsed(eventId))
        {
            throw new InvalidOperationException("event already used");
        }

        return ev;
    }

    private FakeRequest Request { get; } = new();
    private string clientIp = "203.0.113.9";

    public async Task<object> BotSnippetAsync(FpChecker fp)
    {
        var headers = Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString());
        JsonElement? verdict;
        try
        {
            verdict = await fp.BotCheckAsync(Request.Method, $"https://{Request.Host}{Request.Path}{Request.QueryString}", clientIp, headers);
        }
        catch (FpCheckerApiException)
        {
            verdict = null; // fail open: an outage of the check must not take your site down
        }

        var result = verdict is { } v && v.TryGetProperty("bot", out var bot) && bot.TryGetProperty("result", out var r)
            ? r.GetString()
            : null;
        if (result == "bad")
        {
            return Results.StatusCode(403);
        }

        return "ok";
    }

    public async Task<object> WebhookSnippetAsync()
    {
        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms);
        var rawBody = ms.ToArray(); // the exact bytes received, not a re-serialised object
        try
        {
            Webhook.VerifyWebhookSignature(rawBody, Request.Headers["FPC-Signature"].ToString(), Environment.GetEnvironmentVariable("FPC_WEBHOOK_SECRET")!);
        }
        catch (WebhookSignatureException e)
        {
            return Results.BadRequest(); // e.Code: malformed_header | bad_signature | expired | future
        }

        var ev = Events.ParseWebhookEvent(Encoding.UTF8.GetString(rawBody)); // only after verifying
        Console.WriteLine($"{ev.VisitorId} {ev.RuleAction?.Type ?? "none"}");
        return "ok";
    }

    [Fact]
    public async Task EventSnippetRejectsBadShapeBeforeAnyRequest()
    {
        using var fp = new FpChecker(new FpCheckerOptions { SecretKey = "sk_test_x" });
        await Assert.ThrowsAsync<InvalidOperationException>(() => VerifyEventAsync(fp, "nope", new Used()));
    }

    [Fact]
    public async Task WebhookSnippetRejectsMissingSignature()
    {
        Environment.SetEnvironmentVariable("FPC_WEBHOOK_SECRET", "whsec_test");
        var res = await WebhookSnippetAsync();
        Assert.Equal("BadRequest", res.ToString());
    }

    [Fact]
    public void ReadmeStillContainsTheSnippetLines()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "README.md")) ) { dir = Path.GetDirectoryName(dir); }
        var readme = File.ReadAllText(Path.Combine(dir ?? ".", "README.md"));
        foreach (var line in new[]
        {
            "public static async Task<JsonElement> VerifyEventAsync(FpChecker fp, string eventId, IUsedEvents used)",
            "await Request.Body.CopyToAsync(ms);",
            "Webhook.VerifyWebhookSignature(rawBody, Request.Headers[\"FPC-Signature\"].ToString(), Environment.GetEnvironmentVariable(\"FPC_WEBHOOK_SECRET\")!);",
            "var ev = Events.ParseWebhookEvent(Encoding.UTF8.GetString(rawBody)); // only after verifying",
            "var headers = Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString());",
        })
        {
            Assert.Contains(line, readme);
        }
    }

    private sealed class Used : IUsedEvents
    {
        public bool MarkUsed(string eventId) => true;
    }

    private sealed class FakeRequest
    {
        public string Method => "GET";
        public string Host => "example.com";
        public string Path => "/p";
        public string QueryString => "?q=1";
        public Stream Body { get; } = new MemoryStream(Encoding.UTF8.GetBytes("{}"));
        public HeaderBag Headers { get; } = new() { { "User-Agent", new[] { "x" } } };
    }

    private sealed class HeaderBag : Dictionary<string, string[]>
    {
        public new string[] this[string key] => TryGetValue(key, out var v) ? v : Array.Empty<string>();
    }

    private static class Results
    {
        public static object StatusCode(int code) => "StatusCode" + code;
        public static object BadRequest() => "BadRequest";
    }
}
