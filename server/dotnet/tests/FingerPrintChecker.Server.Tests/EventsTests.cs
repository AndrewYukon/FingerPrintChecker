using System.Text.Json;
using Xunit;

namespace FingerPrintChecker.Server.Tests;

public class EventsTests
{
    private static readonly JsonElement V = Vectors.Load("webhook-signature.json");
    private static readonly string Secret = V.GetProperty("secret").GetString()!;

    private static JsonElement Case(string name) => V.GetProperty("cases").EnumerateArray().First(c => c.GetProperty("name").GetString() == name);

    private static string Ev(string dataExtra = "") =>
        "{\"id\":\"evt_1\",\"type\":\"identify\",\"data\":{\"visitorId\":\"v_1\"" + (dataExtra.Length > 0 ? "," + dataExtra : "") + "}}";

    [Fact]
    public void OkRuleActionVectorVerifiesAndParses()
    {
        var c = Case("ok_rule_action");
        var body = c.GetProperty("body").GetString()!;
        Webhook.VerifyWebhookSignature(body, c.GetProperty("header").GetString()!, Secret, now: c.GetProperty("now").GetDouble());
        var e = Events.ParseWebhookEvent(body);
        Assert.True(e.Proxied);
        Assert.Equal(new RuleAction("deny", "r_0a1b2c3d", "Block hosting", 3), e.RuleAction);
    }

    [Theory]
    [InlineData("allow")]
    [InlineData("human_check")]
    [InlineData("deny")]
    [InlineData("none")]
    public void RuleActionTypes(string t)
    {
        var e = Events.ParseWebhookEvent(Ev($"\"ruleAction\":{{\"type\":\"{t}\",\"rulesetVersion\":1}},\"proxied\":false"));
        Assert.Equal(t, e.RuleAction!.Type);
        Assert.Null(e.RuleAction.RuleId);
        Assert.False(e.Proxied);
    }

    [Fact]
    public void NullAndMissingRuleAction()
    {
        var n = Events.ParseWebhookEvent(Ev("\"ruleAction\":null"));
        Assert.Null(n.RuleAction);
        Assert.True(n.RuleActionPresent);
        var old = Events.ParseWebhookEvent(Ev());
        Assert.Null(old.RuleAction);
        Assert.False(old.RuleActionPresent);
        Assert.Null(old.Proxied);
    }

    [Fact]
    public void UnknownRuleTypeDoesNotThrow() =>
        Assert.Equal("captcha", Events.ParseWebhookEvent(Ev("\"ruleAction\":{\"type\":\"captcha\",\"rulesetVersion\":2}")).RuleAction!.Type);

    [Theory]
    [InlineData("{\"a\":1}")]
    [InlineData("not json")]
    [InlineData("[1]")]
    [InlineData("{\"data\":{\"visitorId\":5}}")]
    public void RejectsNonEvent(string body) => Assert.Throws<ArgumentException>(() => Events.ParseWebhookEvent(body));

    [Fact]
    public void EligibilityRuleId()
    {
        using var d1 = JsonDocument.Parse("{\"ok\":true,\"eligible\":false,\"action\":\"deny\",\"reason\":\"rule_deny\",\"ruleId\":\"r_1\"}");
        var a = Events.ParseEligibilityAnswer(d1.RootElement);
        Assert.Equal("r_1", a.RuleId);
        Assert.Equal("rule_deny", a.Reason);
        Assert.False(a.Eligible);
        Assert.True(a.Ok);
        using var d2 = JsonDocument.Parse("{\"ok\":true,\"eligible\":true,\"reason\":\"brand_new\"}");
        Assert.Null(Events.ParseEligibilityAnswer(d2.RootElement).RuleId);
        using var d3 = JsonDocument.Parse("[1]");
        Assert.Throws<ArgumentException>(() => Events.ParseEligibilityAnswer(d3.RootElement));
    }

    [Fact]
    public void OkMobileSignalsVectorVerifiesAndParses()
    {
        var c = Case("ok_mobile_signals");
        var body = c.GetProperty("body").GetString()!;
        Webhook.VerifyWebhookSignature(body, c.GetProperty("header").GetString()!, Secret, now: c.GetProperty("now").GetDouble());
        var e = Events.ParseWebhookEvent(body);
        var m = e.Mobile!;
        Assert.Equal((true, false, true, true, (bool?)null, (string?)null), (m.Rooted, m.Hooked, m.DeveloperMode, m.Vpn, m.LocationSpoofed, m.FactoryResetAt));
        Assert.Contains("os_vpn", e.VpnMethods);
    }

    [Fact]
    public void OldPayloadNewFieldsAreNull()
    {
        var m = Events.ParseWebhookEvent(Ev("\"signals\":{\"mobile\":{\"emulator\":false,\"attested\":true,\"integrity\":\"strong\"}}")).Mobile!;
        Assert.Null(m.Rooted);
        Assert.Null(m.ClonedApp);
        Assert.Null(m.FactoryResetAt);
        Assert.Equal("strong", m.Integrity);
        Assert.Null(Events.ParseWebhookEvent(Ev("\"signals\":{\"mobile\":null}")).Mobile);
        var e = Events.ParseWebhookEvent(Ev());
        Assert.Null(e.Mobile);
        Assert.Empty(e.VpnMethods);
    }

    [Fact]
    public void NonBooleanReadsAsNullAndUnknownVpnMethodKept()
    {
        var e = Events.ParseWebhookEvent(Ev("\"signals\":{\"vpn\":{\"result\":true,\"methods\":[\"os_vpn\",\"future\"]},\"mobile\":{\"rooted\":\"yes\",\"factoryResetAt\":5}}"));
        Assert.Null(e.Mobile!.Rooted);
        Assert.Null(e.Mobile.FactoryResetAt);
        Assert.Equal(new[] { "os_vpn", "future" }, e.VpnMethods);
    }

    [Fact]
    public void V1EventParsesWithoutInfo()
    {
        var e = Events.ParseWebhookEvent(Ev("\"signals\":{\"version\":1,\"bot\":{\"result\":\"bad\",\"types\":[\"webdriver\"]}}"));
        Assert.Equal(1, e.SignalsVersion);
        Assert.Equal("bad", e.Bot!.Result);
        Assert.Equal(new[] { "webdriver" }, e.Bot.Types);
        Assert.Null(e.Bot.Info);
    }

    [Fact]
    public void V2EventParsesGoodAndInfo()
    {
        const string info = "{\"id\":\"googlebot\",\"name\":\"Googlebot\",\"provider\":\"Google\",\"category\":\"search_crawler\",\"identity\":\"verified\"}";
        var e = Events.ParseWebhookEvent(Ev("\"signals\":{\"version\":2,\"bot\":{\"result\":\"good\",\"types\":[],\"info\":" + info + "}}"));
        Assert.Equal(2, e.SignalsVersion);
        Assert.Equal("good", e.Bot!.Result);
        Assert.Equal(new BotInfo("googlebot", "Googlebot", "Google", "search_crawler", "verified"), e.Bot.Info);
        Assert.Null(Events.ParseWebhookEvent(Ev("\"signals\":{\"version\":2,\"bot\":{\"result\":\"not_detected\",\"types\":[],\"info\":null}}")).Bot!.Info);
    }

    [Fact]
    public void EventWithoutSignalsHasNoBot()
    {
        var e = Events.ParseWebhookEvent("{\"data\":{\"visitorId\":\"v_1\"}}");
        Assert.Null(e.Bot);
        Assert.Null(e.SignalsVersion);
    }

    [Fact]
    public void UnknownSignalsVersionIsNull() =>
        Assert.Null(Events.ParseWebhookEvent(Ev("\"signals\":{\"version\":3}")).SignalsVersion);

    [Fact]
    public void RawKeepsTheParsedBody() =>
        Assert.Equal("evt_1", Events.ParseWebhookEvent(Ev()).Raw.GetProperty("id").GetString());
}
