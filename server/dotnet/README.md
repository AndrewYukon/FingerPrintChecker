# FingerPrintChecker.Server

Server SDK for [FingerPrintChecker](https://fpchecker.com). .NET 8, no runtime dependency beyond the base class library.

The package is not on nuget.org yet. Download `FingerPrintChecker.Server.0.1.0.nupkg` from the GitHub release, put it in a folder, and add that folder as a local package source:

```bash
mkdir -p local-packages && cp FingerPrintChecker.Server.0.1.0.nupkg local-packages/
dotnet nuget add source "$(pwd)/local-packages" --name fpchecker-local
dotnet add package FingerPrintChecker.Server --version 0.1.0
```

Quick start:

```csharp
using FingerPrintChecker.Server;

using var fp = new FpChecker(new FpCheckerOptions { SecretKey = Environment.GetEnvironmentVariable("FPCHECKER_SECRET_KEY")! });
var verdict = await fp.CheckEligibilityAsync(new { visitorId = "v_..." });
if (verdict.TryGetProperty("ok", out var ok) && ok.ValueKind == System.Text.Json.JsonValueKind.False)
{
    Console.WriteLine("refused");
}
```

## Client

`new FpChecker(FpCheckerOptions options)` has one async method per OpenAPI `operationId`, with an `Async` suffix: `CreateIntentAsync`, `GetChallengeAsync`, `IdentifyAsync`, `BotCheckAsync`, `CheckEligibilityAsync`, `ReleaseEligibilityAsync`, `CheckQuotaAsync`, `BindSubjectAsync`, `RelateSubjectsAsync`, `SendFeedbackAsync`, `GetClaimFlagsAsync`, `SearchEventsAsync`, `GetEventAsync`, `UpdateEventAsync`, `GetVisitorAsync`, `DeleteVisitorAsync`, `GetHealthAsync`, `GetStatusAsync`. Bodies are any object `System.Text.Json` can serialise; responses are `JsonElement`.

- The secret key goes in the `X-Secret-Key` header, never in a URL, and is not shown by `ToString` or an exception message, and `FpCheckerOptions.SecretKey` is excluded from `System.Text.Json` serialisation (do not log the options object anyway). `GetChallengeAsync` and `IdentifyAsync` use `PublishableKey` in `X-Publishable-Key` instead; `GetHealthAsync` and `GetStatusAsync` send no key.
- 2xx responses are returned as data, **including** refusals such as `{"ok": false, "error": ...}`. Check `ok`.
- Non-2xx throws `FpCheckerApiException` with `Status`, `Code`, `RetryAfter` (seconds) and `Body`. Network failures and timeouts throw it too, with `Status` 0 and code `network_error` or `timeout`.
- Redirects are never followed (they would forward the secret key to another origin). `BaseUrl` must be https, except localhost, 127.0.0.1 and [::1].
- Only GET requests retry (429, 5xx, network failures and timeouts; at most 2 retries, honouring `Retry-After`, wait capped at 10 s).

If you pass your own `HttpMessageHandler` as the second constructor argument, the SDK wraps it so that any 3xx answer is refused (`network_error`, the `Location` header is never read). A handler that is an `HttpClientHandler` or `SocketsHttpHandler` (also behind `DelegatingHandler` wrappers) with `AllowAutoRedirect` on is rejected with `ArgumentException`: set `AllowAutoRedirect = false`. A custom handler type that follows redirects internally cannot be detected, so it must not follow them: that would send the secret key to another host.

## Verifying an eventId

When the browser reports an `eventId`, fetch the event from your server and check it before trusting anything. Do not accept the browser's own claims about the visitor.

```csharp
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using FingerPrintChecker.Server;

/// <summary>Your own store; MarkUsed returns false when the id was seen before (database unique key, Redis SET NX).</summary>
public interface IUsedEvents
{
    bool MarkUsed(string eventId);
}

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
```

## Bot check

`BotCheckAsync(method, url, ip, headers)` classifies a request your backend received (header-only: no script ran in the sender). It is not charged and writes no event. Pass the original URL (the host and scheme the visitor used, not your origin behind a CDN or load balancer) and the trusted client IP. The headers go through `BotHeaders.Filter` inside `BotCheckAsync`: only the headers the check needs are sent, and Cookie and Authorization never leave your process.

```csharp
using System.Text.Json;
using FingerPrintChecker.Server;

// `Request`, `Results` and `clientIp` are ASP.NET minimal-API / controller stand-ins; `fp` is your FpChecker.
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
```

`bot.result` is `good`, `bad` or `not_detected`; `bot.info` (`id`, `name`, `provider`, `category`, `identity`) is set when the request named a directory bot. A 400 throws `FpCheckerApiException` with code `invalid_request` or `invalid_ip` and the offending `field` in `Body`.

Rules of use:
- Call it once per request and reuse the answer.
- Never retry a signed request: a retry replays the signature nonce and the request is then judged `spoofed` (`bad`).
- `ip` must be the trusted client IP, not an address a client can set.
- `BotHeaders.Filter` also keeps any header named in the request's `signature-input`, so signed agents verify.

## Sealed results

```csharp
try
{
    var result = Sealed.UnsealResult(sealedResult, new[] { Environment.GetEnvironmentVariable("FPC_SEALED_KEY")! });
}
catch (SealedResultException e)
{
    // e.Code: bad_format | unknown_key | decrypt_failed | invalid_key | unsupported_version
}
```

Pass every active key (the current and the previous one during rotation). Nothing partial is ever returned.

## Webhooks

```csharp
using System.Text;
using FingerPrintChecker.Server;

// `Request` and `Results` are ASP.NET stand-ins.
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
```

The `string` overload also exists, but read the body as bytes: a text round-trip can alter it. `toleranceSec` (default 300) must be a finite number >= 0, else `ArgumentOutOfRangeException`. `Events.ParseEligibilityAnswer(verdict)` narrows a `CheckEligibilityAsync` response the same way. `WebhookEvent` carries `SignalsVersion` and `Bot` (`BotSignals`). Reasons and rule types are open strings: an unknown value never throws.
