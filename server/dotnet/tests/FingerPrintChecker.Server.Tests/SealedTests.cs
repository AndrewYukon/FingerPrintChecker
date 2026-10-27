using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace FingerPrintChecker.Server.Tests;

public class SealedTests
{
    private static readonly JsonElement V = Vectors.Load("sealed-result-v1.json");
    private static readonly List<JsonElement> Cases = V.GetProperty("cases").EnumerateArray().ToList();

    private static string Key(string name) => V.GetProperty("keys").GetProperty(name).GetString()!;

    public static IEnumerable<object[]> CaseNames() => Cases.Select((c, i) => new object[] { i });

    [Fact]
    public void VectorCountIsNotFiltered() => Assert.Equal(17, Cases.Count);

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void SealedVector(int index)
    {
        var c = Cases[index];
        var keys = c.GetProperty("keys").EnumerateArray().Select(k => Key(k.GetString()!)).ToList();
        var expect = c.GetProperty("expect");
        var blob = c.GetProperty("blob").GetString()!;
        if (expect.TryGetProperty("error", out var err))
        {
            var ex = Assert.Throws<SealedResultException>(() => Sealed.UnsealResult(blob, keys));
            Assert.Equal(err.GetString(), ex.Code);
        }
        else
        {
            Assert.True(Vectors.JsonEq(expect, Sealed.UnsealResult(blob, keys)));
        }
    }

    [Fact]
    public void ErrorCodesCoveredByVectors()
    {
        var codes = Cases.Select(c => c.GetProperty("expect"))
            .Where(e => e.TryGetProperty("error", out _))
            .Select(e => e.GetProperty("error").GetString()!)
            .ToHashSet();
        Assert.Equal(new HashSet<string> { "bad_format", "unknown_key", "decrypt_failed", "invalid_key", "unsupported_version" }, codes);
    }

    [Fact]
    public void InvalidKeyCheckedBeforeBlob()
    {
        var ex = Assert.Throws<SealedResultException>(() => Sealed.UnsealResult("!!!", new[] { Key("short") }));
        Assert.Equal("invalid_key", ex.Code);
    }

    [Fact]
    public void NullKeysIsInvalidKey()
    {
        var ex = Assert.Throws<SealedResultException>(() => Sealed.UnsealResult(Cases[0].GetProperty("blob").GetString()!, null!));
        Assert.Equal("invalid_key", ex.Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not base64!")]
    [InlineData("")]
    public void BadKeyEntriesAreInvalidKey(string? key)
    {
        var ex = Assert.Throws<SealedResultException>(() => Sealed.UnsealResult(Cases[0].GetProperty("blob").GetString()!, new[] { key! }));
        Assert.Equal("invalid_key", ex.Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("abc")]
    public void NonBlobIsBadFormat(string? blob)
    {
        var ex = Assert.Throws<SealedResultException>(() => Sealed.UnsealResult(blob!, new[] { Key("a") }));
        Assert.Equal("bad_format", ex.Code);
    }

    [Fact]
    public void UnicodeDigitsAreNotBase64()
    {
        var ex = Assert.Throws<SealedResultException>(() => Sealed.UnsealResult(new string('Ａ', 48), new[] { Key("a") }));
        Assert.Equal("bad_format", ex.Code);
    }

    [Fact]
    public void TrailingNewlineIsBadFormat()
    {
        var ex = Assert.Throws<SealedResultException>(() => Sealed.UnsealResult(Cases[0].GetProperty("blob").GetString()! + "\n", new[] { Key("a") }));
        Assert.Equal("bad_format", ex.Code);
    }

    [Fact]
    public void ErrorMessageHasNoKeyMaterial()
    {
        var ex = Assert.Throws<SealedResultException>(() => Sealed.UnsealResult(Cases[0].GetProperty("blob").GetString()!, new[] { Key("b") }));
        Assert.DoesNotContain(Key("b"), ex.ToString());
        Assert.DoesNotContain(Key("b"), ex.Message);
    }

    private static string Seal(byte[] payload, string? keyB64 = null)
    {
        var key = Convert.FromBase64String(keyB64 ?? Key("a"));
        var head = Encoding.ASCII.GetBytes("fps1").Concat(SHA256.HashData(key).Take(4)).ToArray();
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[payload.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, payload, ct, tag, head);
        return Convert.ToBase64String(head.Concat(nonce).Concat(ct).Concat(tag).ToArray());
    }

    private static byte[] B(string s) => Encoding.UTF8.GetBytes(s);

    public static IEnumerable<object[]> EdgePayloads() => new[]
    {
        new object[] { B("{\"version\":NaN}") },
        new object[] { B("{\"version\":1,\"x\":Infinity}") },
        new object[] { B("{\"version\":1,\"x\":-Infinity}") },
        new object[] { B(new string('[', 100000) + new string(']', 100000)) },
        new object[] { new byte[] { 0xFF, 0xFE } },
        new object[] { Array.Empty<byte>() },
        new object[] { B("{\"version\":1,\"x\":\"").Concat(new byte[] { 0xFF }).Concat(B("\"}")).ToArray() },
        new object[] { B("{\"version\":1} trailing") },
        new object[] { new byte[] { 0xEF, 0xBB, 0xBF }.Concat(B("{\"version\":1}")).ToArray() },
        new object[] { B("[1]") },
    };

    [Theory]
    [MemberData(nameof(EdgePayloads))]
    public void JsonEdgeCasesAreDecryptFailed(byte[] payload)
    {
        var ex = Assert.Throws<SealedResultException>(() => Sealed.UnsealResult(Seal(payload), new[] { Key("a") }));
        Assert.Equal("decrypt_failed", ex.Code);
    }

    [Theory]
    [InlineData("{\"version\":true}")]
    [InlineData("{\"version\":2}")]
    [InlineData("{\"x\":1}")]
    public void WrongVersionIsUnsupported(string json)
    {
        var ex = Assert.Throws<SealedResultException>(() => Sealed.UnsealResult(Seal(B(json)), new[] { Key("a") }));
        Assert.Equal("unsupported_version", ex.Code);
    }

    [Fact]
    public void SealHelperPositiveControl()
    {
        var r = Sealed.UnsealResult(Seal(B("{\"version\":1,\"x\":2}")), new[] { Key("a") });
        Assert.Equal(2, r.GetProperty("x").GetInt32());
    }
}
