using System.Text.Json;

namespace FingerPrintChecker.Server;

/// <summary>Typed views of webhook events and eligibility answers. Reasons and rule types are open strings: an unknown one never throws.</summary>
public static class Events
{
    private static string? OptStr(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static string OrDefault(string? s, string fallback) => string.IsNullOrEmpty(s) ? fallback : s;

    private static bool? Tri(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? v.ValueKind == JsonValueKind.True
            : null;

    private static JsonElement? Obj(JsonElement o, string name) =>
        o.ValueKind == JsonValueKind.Object && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Object ? v : null;

    private static RuleAction? ParseRuleAction(JsonElement data)
    {
        if (Obj(data, "ruleAction") is not { } v || OptStr(v, "type") is not { } type)
        {
            return null;
        }

        var version = v.TryGetProperty("rulesetVersion", out var rv) && rv.ValueKind == JsonValueKind.Number && rv.TryGetInt64(out var n) ? n : 0;
        return new RuleAction(type, OptStr(v, "ruleId"), OptStr(v, "ruleName"), version);
    }

    private static MobileSignals? ParseMobile(JsonElement signals)
    {
        if (Obj(signals, "mobile") is not { } v)
        {
            return null;
        }

        var integrity = OptStr(v, "integrity");
        return new MobileSignals(
            Tri(v, "emulator"),
            Tri(v, "attested"),
            integrity is "strong" or "basic" or "failed" ? integrity : null,
            Tri(v, "rooted"),
            Tri(v, "hooked"),
            Tri(v, "debugger"),
            Tri(v, "developerMode"),
            Tri(v, "mitm"),
            Tri(v, "vpn"),
            Tri(v, "locationSpoofed"),
            Tri(v, "clonedApp"),
            OptStr(v, "factoryResetAt"));
    }

    private static List<string> Strings(JsonElement o, string name)
    {
        var list = new List<string>();
        if (o.TryGetProperty(name, out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            list.AddRange(arr.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!));
        }

        return list;
    }

    private static BotSignals? ParseBot(JsonElement signals)
    {
        if (Obj(signals, "bot") is not { } v)
        {
            return null;
        }

        BotInfo? info = null;
        if (Obj(v, "info") is { } i && OptStr(i, "id") is { } id)
        {
            info = new BotInfo(
                id,
                OrDefault(OptStr(i, "name"), string.Empty),
                OrDefault(OptStr(i, "provider"), string.Empty),
                OrDefault(OptStr(i, "category"), "other"),
                OrDefault(OptStr(i, "identity"), "unknown"));
        }

        return new BotSignals(OptStr(v, "result"), Strings(v, "types"), info);
    }

    /// <summary>Parse a webhook body (verify its signature first).</summary>
    /// <exception cref="ArgumentException">The body is not JSON or not a webhook event.</exception>
    public static WebhookEvent ParseWebhookEvent(string rawBody)
    {
        ArgumentNullException.ThrowIfNull(rawBody);
        JsonElement body;
        try
        {
            using var doc = JsonDocument.Parse(rawBody);
            body = doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw new ArgumentException("ParseWebhookEvent: not JSON", nameof(rawBody));
        }

        if (Obj(body, "data") is not { } data || OptStr(data, "visitorId") is not { } visitorId)
        {
            throw new ArgumentException("ParseWebhookEvent: not a webhook event", nameof(rawBody));
        }

        var signals = Obj(data, "signals") ?? default;
        var vpn = signals.ValueKind == JsonValueKind.Object ? Obj(signals, "vpn") : null;
        int? signalsVersion = signals.ValueKind == JsonValueKind.Object
            && signals.TryGetProperty("version", out var sv)
            && sv.ValueKind == JsonValueKind.Number
            && sv.TryGetInt32(out var vn)
            && vn is 1 or 2
                ? vn
                : null;
        return new WebhookEvent(
            visitorId,
            Tri(data, "proxied"),
            ParseRuleAction(data),
            data.TryGetProperty("ruleAction", out _),
            signals.ValueKind == JsonValueKind.Object ? ParseMobile(signals) : null,
            vpn is { } vp ? Strings(vp, "methods") : new List<string>(),
            body,
            signalsVersion,
            signals.ValueKind == JsonValueKind.Object ? ParseBot(signals) : null);
    }

    /// <summary>Narrow a CheckEligibility response; <c>RuleId</c> is surfaced when present.</summary>
    /// <exception cref="ArgumentException">The value is not a JSON object.</exception>
    public static EligibilityAnswer ParseEligibilityAnswer(JsonElement body)
    {
        if (body.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("ParseEligibilityAnswer: not an object", nameof(body));
        }

        return new EligibilityAnswer(
            Tri(body, "ok") == true,
            Tri(body, "eligible"),
            OptStr(body, "action"),
            OptStr(body, "reason"),
            OptStr(body, "ruleId"),
            body);
    }
}
