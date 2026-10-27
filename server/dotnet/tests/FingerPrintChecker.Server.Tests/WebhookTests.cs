using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace FingerPrintChecker.Server.Tests;

public class WebhookTests
{
    private static readonly JsonElement V = Vectors.Load("webhook-signature.json");
    private static readonly List<JsonElement> Cases = V.GetProperty("cases").EnumerateArray().ToList();
    private static readonly string Secret = V.GetProperty("secret").GetString()!;

    public static IEnumerable<object[]> CaseNames() => Cases.Select((c, i) => new object[] { i });

    [Fact]
    public void VectorCountIsNotFiltered() => Assert.Equal(17, Cases.Count);

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void WebhookVector(int index)
    {
        var c = Cases[index];
        var body = Encoding.UTF8.GetBytes(c.GetProperty("body").GetString()!);
        var header = c.GetProperty("header").GetString()!;
        var now = c.GetProperty("now").GetDouble();
        var expect = c.GetProperty("expect");
        if (expect.ValueKind == JsonValueKind.True)
        {
            Webhook.VerifyWebhookSignature(body, header, Secret, now: now);
        }
        else
        {
            var ex = Assert.Throws<WebhookSignatureException>(() => Webhook.VerifyWebhookSignature(body, header, Secret, now: now));
            Assert.Equal(expect.GetProperty("error").GetString(), ex.Code);
        }
    }

    private static string Sign(byte[] body, long t, string? secret = null)
    {
        var msg = Encoding.ASCII.GetBytes(t + ".").Concat(body).ToArray();
        return $"t={t},v1={Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret ?? Secret), msg)).ToLowerInvariant()}";
    }

    private static readonly byte[] Empty = Encoding.UTF8.GetBytes("{}");

    [Fact]
    public void StringBodyAcceptedAndDefaultNow()
    {
        var t = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        const string body = "{\"a\":\"é\"}";
        Webhook.VerifyWebhookSignature(body, Sign(Encoding.UTF8.GetBytes(body), t), Secret);
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    [InlineData(-1.0)]
    [InlineData(-0.5)]
    public void ToleranceMustBeFiniteNonNegative(double tol)
    {
        Assert.ThrowsAny<ArgumentException>(() => Webhook.VerifyWebhookSignature(Empty, Sign(Empty, 1000), Secret, tol, 1000));
    }

    [Fact]
    public void NonFiniteNowRejected()
    {
        Assert.ThrowsAny<ArgumentException>(() => Webhook.VerifyWebhookSignature(Empty, Sign(Empty, 1000), Secret, 300, double.NaN));
    }

    [Fact]
    public void ToleranceZeroAndFloat()
    {
        Webhook.VerifyWebhookSignature(Empty, Sign(Empty, 1000), Secret, 0, 1000);
        var ex = Assert.Throws<WebhookSignatureException>(() => Webhook.VerifyWebhookSignature(Empty, Sign(Empty, 1000), Secret, 0, 1001));
        Assert.Equal("expired", ex.Code);
        Webhook.VerifyWebhookSignature(Empty, Sign(Empty, 1000), Secret, 1.5, 1001);
    }

    [Fact]
    public void NullHeaderIsMalformed()
    {
        var ex = Assert.Throws<WebhookSignatureException>(() => Webhook.VerifyWebhookSignature(Empty, null!, Secret, now: 1));
        Assert.Equal("malformed_header", ex.Code);
    }

    [Theory]
    [InlineData("t=١٢,v1=0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("t=1234567890123,v1=0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("t=1,v0=0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("t=1,t=2,v1=0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("t=1, v1=0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("t=1,v1=0000000000000000000000000000000000000000000000000000000000000000\n")]
    public void MalformedHeaders(string header)
    {
        var ex = Assert.Throws<WebhookSignatureException>(() => Webhook.VerifyWebhookSignature(Empty, header, Secret, now: 1));
        Assert.Equal("malformed_header", ex.Code);
    }

    [Fact]
    public void AnyValidCandidateAmongSeveralPasses()
    {
        var good = Sign(Empty, 5);
        var header = "t=5,v1=" + new string('0', 64) + ",v1=zz," + good[(good.IndexOf("v1=", StringComparison.Ordinal))..];
        Webhook.VerifyWebhookSignature(Empty, header, Secret, now: 5);
    }

    [Fact]
    public void ValidSignatureOutsideToleranceIsRejectedBeforeAnythingElse()
    {
        var ex = Assert.Throws<WebhookSignatureException>(() => Webhook.VerifyWebhookSignature(Empty, Sign(Empty, 1000), Secret, 300, 5000));
        Assert.Equal("expired", ex.Code);
        ex = Assert.Throws<WebhookSignatureException>(() => Webhook.VerifyWebhookSignature(Empty, Sign(Empty, 5000), Secret, 300, 1000));
        Assert.Equal("future", ex.Code);
    }

    [Fact]
    public void LoneSurrogateStringBodyIsReplacementChar()
    {
        var body = "a\ud800b";
        Webhook.VerifyWebhookSignature(body, Sign(Encoding.UTF8.GetBytes("a�b"), 7), Secret, now: 7);
        var ex = Assert.Throws<WebhookSignatureException>(() => Webhook.VerifyWebhookSignature(body, Sign(Encoding.UTF8.GetBytes("a?b"), 7), Secret, now: 7));
        Assert.Equal("bad_signature", ex.Code);
    }

    [Fact]
    public void ErrorMessageHasNoSecretOrSignature()
    {
        var header = Sign(Empty, 5);
        var ex = Assert.Throws<WebhookSignatureException>(() => Webhook.VerifyWebhookSignature(Empty, header, "other-secret", now: 5));
        Assert.DoesNotContain("other-secret", ex.ToString());
        Assert.DoesNotContain(header[(header.IndexOf("v1=", StringComparison.Ordinal) + 3)..], ex.ToString());
    }
}
