using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using Xunit;
using static FingerPrintChecker.Server.Tests.FakeHandler;

namespace FingerPrintChecker.Server.Tests;

public class FpCheckerTests
{
    private const string SK = "sk_test_123";
    private const string PK = "pk_test_9";

    private static readonly JsonElement Spec = LoadSpec();

    private static JsonElement LoadSpec()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "openapi", "fpchecker-api.json")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(dir!.FullName, "openapi", "fpchecker-api.json")));
        return doc.RootElement.Clone();
    }

    private static List<TimeSpan> NoSleep(out Func<TimeSpan, CancellationToken, Task> delay)
    {
        var sleeps = new List<TimeSpan>();
        delay = (t, _) =>
        {
            sleeps.Add(t);
            return Task.CompletedTask;
        };
        return sleeps;
    }

    private static (FpChecker Client, FakeHandler Handler, List<TimeSpan> Sleeps) Mk(
        object[] responses, string? pk = null, string baseUrl = "https://api.fpchecker.com", TimeSpan? timeout = null)
    {
        var handler = new FakeHandler(responses);
        var sleeps = NoSleep(out var delay);
        var client = new FpChecker(
            new FpCheckerOptions { SecretKey = SK, PublishableKey = pk, BaseUrl = baseUrl, Timeout = timeout ?? TimeSpan.FromSeconds(10) },
            handler,
            delay);
        return (client, handler, sleeps);
    }

    private static object[] R(params Func<HttpResponseMessage>[] r) => r.Cast<object>().ToArray();

    // --- surface ---

    private sealed record Op(string Id, string Method, string Path, List<string> PathParams, List<string> QueryParams, bool HasBody, List<string> Security);

    private static List<Op> Operations()
    {
        var ops = new List<Op>();
        var rootSecurity = Spec.TryGetProperty("security", out var rs) ? rs : default;
        foreach (var p in Spec.GetProperty("paths").EnumerateObject())
        {
            foreach (var m in p.Value.EnumerateObject())
            {
                if (m.Value.ValueKind != JsonValueKind.Object || !m.Value.TryGetProperty("operationId", out var id))
                {
                    continue;
                }

                var parameters = new List<JsonElement>();
                if (p.Value.TryGetProperty("parameters", out var pp))
                {
                    parameters.AddRange(pp.EnumerateArray().Select(Deref));
                }

                if (m.Value.TryGetProperty("parameters", out var op))
                {
                    parameters.AddRange(op.EnumerateArray().Select(Deref));
                }

                var secEl = m.Value.TryGetProperty("security", out var s) ? s : rootSecurity;
                var sec = secEl.ValueKind == JsonValueKind.Array
                    ? secEl.EnumerateArray().SelectMany(x => x.EnumerateObject().Select(k => k.Name)).ToList()
                    : new List<string>();
                if (sec.Contains("managementKey"))
                {
                    continue; // the account-level management API is not part of this SDK
                }

                ops.Add(new Op(
                    id.GetString()!,
                    m.Name.ToUpperInvariant(),
                    p.Name,
                    parameters.Where(x => x.GetProperty("in").GetString() == "path").Select(x => x.GetProperty("name").GetString()!).ToList(),
                    parameters.Where(x => x.GetProperty("in").GetString() == "query").Select(x => x.GetProperty("name").GetString()!).ToList(),
                    m.Value.TryGetProperty("requestBody", out _),
                    sec));
            }
        }

        return ops;
    }

    private static JsonElement Deref(JsonElement p)
    {
        if (!p.TryGetProperty("$ref", out var r))
        {
            return p;
        }

        var o = Spec;
        foreach (var k in r.GetString()!.Split('/').Skip(1))
        {
            o = o.GetProperty(k);
        }

        return o;
    }

    public static IEnumerable<object[]> OpIds() => Operations().Select(o => new object[] { o.Id });

    private static string Pascal(string id) => char.ToUpperInvariant(id[0]) + id.Substring(1) + "Async";

    [Fact]
    public void OpTableComplete() => Assert.Equal(18, Operations().Count);

    [Fact]
    public void EveryOperationIdHasMethod() =>
        Assert.Empty(Operations().Where(o => typeof(FpChecker).GetMethod(Pascal(o.Id), BindingFlags.Public | BindingFlags.Instance) is null).Select(o => o.Id));

    [Theory]
    [MemberData(nameof(OpIds))]
    public async Task OperationTable(string opId)
    {
        var op = Operations().Single(o => o.Id == opId);
        var (client, handler, _) = Mk(R(Resp(200, new { ok = true })), PK);
        var method = typeof(FpChecker).GetMethod(Pascal(op.Id), BindingFlags.Public | BindingFlags.Instance)!;
        var ids = op.PathParams.Select((_, i) => (object)$"id/{i} x").ToList();
        var args = new List<object?>();
        var next = 0;
        foreach (var prm in method.GetParameters())
        {
            if (prm.ParameterType == typeof(CancellationToken))
            {
                args.Add(CancellationToken.None);
            }
            else if (prm.Name == "method")
            {
                args.Add("GET");
            }
            else if (prm.Name == "url")
            {
                args.Add("https://x.test/");
            }
            else if (prm.Name == "ip")
            {
                args.Add("1.1.1.1");
            }
            else if (prm.Name == "headers")
            {
                args.Add(new Dictionary<string, string>());
            }
            else if (prm.ParameterType == typeof(string))
            {
                args.Add(ids[next++]);
            }
            else if (prm.Name == "body")
            {
                args.Add(new { a = 1 });
            }
            else
            {
                args.Add(new Dictionary<string, object?> { ["intent"] = "i" });
            }
        }

        var task = (Task<JsonElement>)method.Invoke(client, args.ToArray())!;
        var result = await task;
        Assert.True(result.GetProperty("ok").GetBoolean());

        var call = handler.Calls[0];
        var expected = op.Path;
        for (var i = 0; i < op.PathParams.Count; i++)
        {
            expected = expected.Replace("{" + op.PathParams[i] + "}", Uri.EscapeDataString($"id/{i} x"));
        }

        Assert.Equal(expected, call.Path);
        Assert.Equal(op.Method, call.Method);
        Assert.Equal(op.Security.Contains("secretKey"), call.Header("X-Secret-Key") is not null);
        Assert.Equal(op.Security.Contains("publishableKey"), call.Header("X-Publishable-Key") is not null);
        if (op.Security.Contains("secretKey"))
        {
            Assert.Equal(SK, call.Header("X-Secret-Key"));
        }

        if (op.Security.Contains("publishableKey"))
        {
            Assert.Equal(PK, call.Header("X-Publishable-Key"));
        }

        Assert.DoesNotContain("sk_test", call.Url);
        Assert.DoesNotContain("pk_test", call.Url);
        Assert.Equal("fpchecker-dotnet/0.1.0", call.Header("User-Agent"));
        Assert.Equal("application/json", call.Header("Accept"));
    }

    // --- construction ---

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void RequiresSecretKey(string? bad) =>
        Assert.Throws<ArgumentException>(() => new FpChecker(new FpCheckerOptions { SecretKey = bad! }));

    [Fact]
    public void NullOptionsRejected() => Assert.Throws<ArgumentNullException>(() => new FpChecker(null!));

    [Fact]
    public void ToStringHidesKeys()
    {
        var opts = new FpCheckerOptions { SecretKey = SK, PublishableKey = PK };
        using var c = new FpChecker(opts);
        foreach (var text in new[] { c.ToString()!, opts.ToString()! })
        {
            Assert.DoesNotContain(SK, text);
            Assert.DoesNotContain(PK, text);
        }
    }

    [Fact]
    public async Task QueryEncodingAndBaseUrl()
    {
        var (client, handler, _) = Mk(R(Resp(200, new { })), baseUrl: "https://x.test/");
        await client.SearchEventsAsync(new Dictionary<string, object?> { ["visitorId"] = "v 1", ["bot"] = true, ["off"] = false, ["limit"] = 5, ["linkedId"] = null });
        Assert.Equal("https://x.test/v1/events?visitorId=v+1&bot=true&off=false&limit=5", handler.Calls[0].Url);
    }

    [Fact]
    public async Task QueryKeysAndValuesEncodedLikeQuotePlus()
    {
        var (client, handler, _) = Mk(R(Resp(200, new { })));
        await client.SearchEventsAsync(new Dictionary<string, object?> { ["a b&c"] = "x=y/z~é+" });
        Assert.Equal("https://api.fpchecker.com/v1/events?a+b%26c=x%3Dy%2Fz~%C3%A9%2B", handler.Calls[0].Url);
    }

    [Fact]
    public async Task MobileSignalFiltersAreForwarded()
    {
        var (client, handler, _) = Mk(R(Resp(200, new { })));
        await client.SearchEventsAsync(new Dictionary<string, object?>
        {
            ["rooted"] = true, ["hooked"] = false, ["emulator"] = true, ["mitm"] = true, ["locationSpoofed"] = false, ["clonedApp"] = true,
        });
        Assert.Equal(
            "https://api.fpchecker.com/v1/events?rooted=true&hooked=false&emulator=true&mitm=true&locationSpoofed=false&clonedApp=true",
            handler.Calls[0].Url);
    }

    [Fact]
    public async Task PathParamEncoded()
    {
        var (client, handler, _) = Mk(R(Resp(200, new { })));
        await client.GetVisitorAsync("a/b");
        Assert.Equal("https://api.fpchecker.com/v1/visitors/a%2Fb", handler.Calls[0].Url);
    }

    [Theory]
    [InlineData("a?b", "a%3Fb")]
    [InlineData("a#b", "a%23b")]
    [InlineData("a%2Fb", "a%252Fb")]
    [InlineData("a b~c.d_e-f", "a%20b~c.d_e-f")]
    [InlineData("é", "%C3%A9")]
    [InlineData("..a", "..a")]
    public async Task PathIdsCannotChangeTheRoute(string id, string encoded)
    {
        var (client, handler, _) = Mk(R(Resp(200, new { })));
        await client.GetEventAsync(id);
        Assert.Equal("https://api.fpchecker.com/v1/events/" + encoded, handler.Calls[0].Url);
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData(null)]
    public async Task RouteChangingPathIdsRejectedWithoutRequest(string? id)
    {
        var (client, handler, _) = Mk(R(Resp(200, new { })));
        Assert.Throws<ArgumentException>(() => { _ = client.GetEventAsync(id!); });
        Assert.Throws<ArgumentException>(() => { _ = client.UpdateEventAsync(id!, new { }); });
        Assert.Throws<ArgumentException>(() => { _ = client.GetVisitorAsync(id!); });
        Assert.Throws<ArgumentException>(() => { _ = client.DeleteVisitorAsync(id!); });
        Assert.Empty(handler.Calls);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task PostSendsJson()
    {
        var (client, handler, _) = Mk(R(Resp(200, new { ok = true })));
        await client.CheckEligibilityAsync(new { visitorId = "v_1" });
        var c = handler.Calls[0];
        Assert.Equal("POST", c.Method);
        Assert.Equal("{\"visitorId\":\"v_1\"}", System.Text.Encoding.UTF8.GetString(c.Body!));
        Assert.Equal("application/json", c.Header("Content-Type"));
    }

    [Fact]
    public async Task BotCheckPostsMethodUrlIpAndHeaders()
    {
        var (client, handler, _) = Mk(R(Resp(200, new { ok = true })));
        await client.BotCheckAsync("GET", "https://shop.test/p", "9.9.9.9", new Dictionary<string, string> { ["user-agent"] = "curl/8" });
        var body = JsonDocument.Parse(handler.Calls[0].Body!).RootElement;
        Assert.Equal("GET", body.GetProperty("method").GetString());
        Assert.Equal("https://shop.test/p", body.GetProperty("url").GetString());
        Assert.Equal("9.9.9.9", body.GetProperty("ip").GetString());
        Assert.Equal("curl/8", body.GetProperty("headers").GetProperty("user-agent").GetString());
        Assert.Equal("/v1/bot-check", handler.Calls[0].Path);
    }

    [Fact]
    public async Task SecretNotSentOnPublishableOpsAndViceVersa()
    {
        var (client, handler, _) = Mk(R(Resp(200, new { }), Resp(200, new { })), PK);
        await client.IdentifyAsync(new { });
        await client.GetHealthAsync();
        Assert.Null(handler.Calls[0].Header("X-Secret-Key"));
        Assert.Equal(PK, handler.Calls[0].Header("X-Publishable-Key"));
        Assert.Null(handler.Calls[1].Header("X-Secret-Key"));
        Assert.Null(handler.Calls[1].Header("X-Publishable-Key"));
    }

    [Fact]
    public async Task PublishableOpsNeedKey()
    {
        var (client, handler, _) = Mk(R());
        Assert.Throws<InvalidOperationException>(() => { _ = client.IdentifyAsync(new { }); });
        Assert.Throws<InvalidOperationException>(() => { _ = client.GetChallengeAsync(new Dictionary<string, object?> { ["intent"] = "i" }); });
        Assert.Empty(handler.Calls);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task TwoXxOkFalseReturnedAsData()
    {
        var (client, _, _) = Mk(R(Resp(200, new { ok = false, reason = "quota_exhausted" })));
        var r = await client.CheckQuotaAsync(new { });
        Assert.False(r.GetProperty("ok").GetBoolean());
        Assert.Equal("quota_exhausted", r.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task TwoXxEmptyOrNonJsonIsEmptyObject()
    {
        var (client, _, _) = Mk(R(Resp(204), Resp(200, "<html>"), Resp(200, "null"), Resp(200, "{} trailing")));
        for (var i = 0; i < 4; i++)
        {
            var r = await client.GetHealthAsync();
            Assert.Equal(JsonValueKind.Object, r.ValueKind);
            Assert.Empty(r.EnumerateObject());
        }
    }

    // --- errors ---

    [Fact]
    public async Task NonTwoXxErrorCode()
    {
        var (client, _, _) = Mk(R(Resp(403, new { ok = false, error = "forbidden" })));
        var e = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetEventAsync("e"));
        Assert.Equal(403, e.Status);
        Assert.Equal("forbidden", e.Code);
        Assert.Null(e.RetryAfter);
        Assert.Equal("forbidden", e.Body!.Value.GetProperty("error").GetString());
    }

    [Fact]
    public async Task CodeFallsBackToReasonThenNone()
    {
        var (client, _, _) = Mk(R(Resp(400, new { ok = false, reason = "bad_input" }), Resp(502, "<html>")));
        var a = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.UpdateEventAsync("e", new { }));
        Assert.Equal("bad_input", a.Code);
        var b = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.CreateIntentAsync(new { }));
        Assert.Equal(502, b.Status);
        Assert.Null(b.Code);
        Assert.Null(b.Body);
    }

    [Fact]
    public async Task ErrorNeverContainsSecret()
    {
        var (client, _, _) = Mk(R(Resp(401, new { error = "bad_key" })));
        var e = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetEventAsync("e"));
        Assert.DoesNotContain(SK, e.Message + e + e.StackTrace);
    }

    // --- retries ---

    [Fact]
    public async Task GetRetriedOn503WithRetryAfter()
    {
        var (client, handler, sleeps) = Mk(R(Resp(503, new { error = "u" }, ("Retry-After", "2")), Resp(200, new { ok = true })));
        var r = await client.GetVisitorAsync("v");
        Assert.True(r.GetProperty("ok").GetBoolean());
        Assert.Equal(2, handler.Calls.Count);
        Assert.Equal(new[] { TimeSpan.FromSeconds(2) }, sleeps);
    }

    [Fact]
    public async Task GetGivesUpAfterTwoRetries()
    {
        var (client, handler, sleeps) = Mk(R(Resp(500, new { }), Resp(500, new { }), Resp(429, new { error = "rate" }, ("Retry-After", "1"))));
        var e = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetHealthAsync());
        Assert.Equal(3, handler.Calls.Count);
        Assert.Equal(429, e.Status);
        Assert.Equal(1, e.RetryAfter);
        Assert.Equal(new[] { TimeSpan.FromSeconds(0.5), TimeSpan.FromSeconds(1) }, sleeps);
    }

    [Fact]
    public async Task RetryAfterCapped()
    {
        var (client, _, sleeps) = Mk(R(Resp(429, new { }, ("Retry-After", "3600")), Resp(200, new { })));
        await client.GetStatusAsync();
        Assert.Equal(TimeSpan.FromSeconds(10), sleeps[0]);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("1.5")]
    [InlineData("1234567890")]
    [InlineData("")]
    [InlineData("soon")]
    public async Task MalformedRetryAfterIgnored(string value)
    {
        var (client, _, sleeps) = Mk(R(Resp(503, new { }, ("Retry-After", value)), Resp(503, new { }, ("Retry-After", value)), Resp(503, new { }, ("Retry-After", value))));
        var e = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetHealthAsync());
        Assert.Null(e.RetryAfter);
        Assert.Equal(new[] { TimeSpan.FromSeconds(0.5), TimeSpan.FromSeconds(1) }, sleeps);
    }

    [Fact]
    public async Task NoRetryOnOther4xx()
    {
        var (client, handler, _) = Mk(R(Resp(404, new { error = "not_found" })));
        await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetEventAsync("x"));
        Assert.Single(handler.Calls);
    }

    [Theory]
    [InlineData(429)]
    [InlineData(503)]
    public async Task BilledPostNeverRetried(int status)
    {
        var (client, handler, _) = Mk(R(Resp(status, new { error = "x" }, ("Retry-After", "1")), Resp(200, new { })));
        await Assert.ThrowsAsync<FpCheckerApiException>(() => client.CheckEligibilityAsync(new { visitorId = "v" }));
        Assert.Single(handler.Calls);
    }

    [Fact]
    public async Task PatchDeleteNeverRetried()
    {
        var (a, ah, _) = Mk(R(Resp(503, new { }), Resp(200, new { })));
        await Assert.ThrowsAsync<FpCheckerApiException>(() => a.UpdateEventAsync("e", new { }));
        var (b, bh, _) = Mk(R(Resp(503, new { }), Resp(200, new { })));
        await Assert.ThrowsAsync<FpCheckerApiException>(() => b.DeleteVisitorAsync("v"));
        Assert.Single(ah.Calls);
        Assert.Single(bh.Calls);
    }

    // --- network ---

    [Fact]
    public async Task NetworkErrorWrapped()
    {
        var (client, handler, _) = Mk(new object[] { new HttpRequestException("refused") });
        var e = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.CheckQuotaAsync(new { }));
        Assert.Equal(0, e.Status);
        Assert.Equal("network_error", e.Code);
        Assert.Single(handler.Calls);
    }

    [Fact]
    public async Task UnknownTransportFailureNeverLeaksSecret()
    {
        var (client, _, _) = Mk(new object[]
        {
            new HttpRequestException("bad header value " + SK, new InvalidOperationException(SK)),
            new FormatException(SK),
            new InvalidOperationException(SK),
        });
        var e = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetHealthAsync());
        Assert.Equal((0, "network_error"), (e.Status, e.Code));
        Assert.Null(e.InnerException);
        Assert.DoesNotContain(SK, e.Message + e + e.StackTrace);
    }

    [Fact]
    public async Task TimeoutExceptionsWrapped()
    {
        var (client, _, _) = Mk(new object[] { new TimeoutException("t"), new TimeoutException("t"), new TimeoutException("t") });
        var e = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetHealthAsync());
        Assert.Equal((0, "timeout"), (e.Status, e.Code));
    }

    [Fact]
    public async Task SlowServerTimesOutPerAttempt()
    {
        Func<CancellationToken, Task<HttpResponseMessage>> hang = async ct =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage();
        };
        var (client, handler, sleeps) = Mk(new object[] { hang, hang, hang }, timeout: TimeSpan.FromMilliseconds(50));
        var e = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetHealthAsync());
        Assert.Equal((0, "timeout"), (e.Status, e.Code));
        Assert.Equal(3, handler.Calls.Count);
        Assert.Equal(2, sleeps.Count);
    }

    [Fact]
    public async Task CallerCancellationPropagates()
    {
        Func<CancellationToken, Task<HttpResponseMessage>> hang = async ct =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage();
        };
        var (client, handler, sleeps) = Mk(new object[] { hang, hang, hang });
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetHealthAsync(cts.Token));
        Assert.Single(handler.Calls);
        Assert.Empty(sleeps);
    }

    [Fact]
    public async Task GetRetriesNetworkFailuresAtMostTwice()
    {
        var (client, handler, _) = Mk(new object[] { new HttpRequestException("a"), new HttpRequestException("b"), new HttpRequestException("c"), Resp(200, new { }) });
        var e = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetVisitorAsync("v"));
        Assert.Equal(3, handler.Calls.Count);
        Assert.Equal("network_error", e.Code);
        var (ok, _, _) = Mk(new object[] { new HttpRequestException("a"), Resp(200, new { ok = true }) });
        Assert.True((await ok.GetVisitorAsync("v")).GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async Task NonGetNeverRetriesNetworkFailures()
    {
        var calls = new Func<FpChecker, Task>[]
        {
            c => c.UpdateEventAsync("e", new { }),
            c => c.DeleteVisitorAsync("v"),
            c => c.CheckEligibilityAsync(new { }),
        };
        foreach (var call in calls)
        {
            var (client, handler, _) = Mk(new object[] { new HttpRequestException("x"), Resp(200, new { }) });
            await Assert.ThrowsAsync<FpCheckerApiException>(() => call(client));
            Assert.Single(handler.Calls);
        }
    }

    // --- redirects (D1) ---

    [Theory]
    [InlineData(301)]
    [InlineData(302)]
    [InlineData(303)]
    [InlineData(307)]
    [InlineData(308)]
    public async Task AnyThreeXxIsNetworkErrorAndLocationIsNeverRead(int status)
    {
        var (client, handler, sleeps) = Mk(R(
            Resp(status, null, ("Location", "https://evil.test/x")),
            Resp(status, null, ("Location", "https://evil.test/x")),
            Resp(status, null, ("Location", "https://evil.test/x"))));
        var e = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetHealthAsync());
        Assert.Equal((0, "network_error"), (e.Status, e.Code));
        Assert.Equal(3, handler.Calls.Count); // GET retried like Python, always against the original host
        Assert.All(handler.Calls, c => Assert.StartsWith("https://api.fpchecker.com/", c.Url));
        Assert.Equal(2, sleeps.Count);

        var (post, ph, _) = Mk(R(Resp(status, null, ("Location", "https://evil.test/x"))));
        var pe = await Assert.ThrowsAsync<FpCheckerApiException>(() => post.CheckQuotaAsync(new { }));
        Assert.Equal((0, "network_error"), (pe.Status, pe.Code));
        Assert.Single(ph.Calls);
    }

    [Theory]
    [InlineData(301)]
    [InlineData(302)]
    [InlineData(307)]
    [InlineData(308)]
    public async Task RealSocketRedirectNeverReachesSecondHost(int status)
    {
        using var target = new TinyServer(_ => TinyServer.Json(200, "OK", "{}"));
        using var redirector = new TinyServer(_ => TinyServer.Raw($"HTTP/1.1 {status} Moved\r\nLocation: {target.BaseUrl}/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
        var sleeps = NoSleep(out var delay);
        using var client = new FpChecker(new FpCheckerOptions { SecretKey = SK, BaseUrl = redirector.BaseUrl, Timeout = TimeSpan.FromSeconds(5) }, null, delay);

        var get = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetHealthAsync());
        Assert.Equal((0, "network_error"), (get.Status, get.Code));
        var post = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.CheckQuotaAsync(new { }));
        Assert.Equal((0, "network_error"), (post.Status, post.Code));

        Assert.Empty(target.Requests);
        Assert.Equal(4, redirector.Requests.Count); // 3 GET attempts + 1 POST
        Assert.Equal(2, sleeps.Count);
    }

    [Fact]
    public void ConstructorRejectsHandlerThatFollowsRedirects()
    {
        var opts = new FpCheckerOptions { SecretKey = SK };
        Assert.Throws<ArgumentException>(() => new FpChecker(opts, new HttpClientHandler()));
        Assert.Throws<ArgumentException>(() => new FpChecker(opts, new SocketsHttpHandler()));
        Assert.Throws<ArgumentException>(() => new FpChecker(opts, new HttpClientHandler { AllowAutoRedirect = true }));
    }

    [Fact]
    public void AcceptsHandlerWithRedirectsOff()
    {
        var opts = new FpCheckerOptions { SecretKey = SK };
        using var a = new FpChecker(opts, new HttpClientHandler { AllowAutoRedirect = false });
        using var b = new FpChecker(opts, new SocketsHttpHandler { AllowAutoRedirect = false });
        using var c = new FpChecker(opts, new FakeHandler());
        using var d = new FpChecker(opts);
    }

    // --- real sockets ---

    [Fact]
    public async Task RealRoundtripSendsSecretHeader()
    {
        using var server = new TinyServer(_ => TinyServer.Json(200, "OK", "{\"ok\":true}"));
        using var client = new FpChecker(new FpCheckerOptions { SecretKey = SK, BaseUrl = server.BaseUrl, Timeout = TimeSpan.FromSeconds(5) });
        var r = await client.GetEventAsync("e 1");
        Assert.True(r.GetProperty("ok").GetBoolean());
        var head = Assert.Single(server.Requests);
        Assert.StartsWith("GET /v1/events/e%201 HTTP/1.1", head);
        Assert.Contains("X-Secret-Key: " + SK, head);
        Assert.DoesNotContain(SK, head.Split("\r\n")[0]);
    }

    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")]
    [InlineData("garbage\r\n\r\n")]
    [InlineData("HTTP/1.1 500 X\r\nContent-Length: 100\r\n\r\n{")]
    public async Task MalformedHttpWrappedAndGetRetried(string payload)
    {
        using var server = new TinyServer(_ => TinyServer.Raw(payload));
        var sleeps = NoSleep(out var delay);
        using var client = new FpChecker(new FpCheckerOptions { SecretKey = SK, BaseUrl = server.BaseUrl, Timeout = TimeSpan.FromSeconds(5) }, null, delay);
        var get = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.GetHealthAsync());
        Assert.Equal((0, "network_error"), (get.Status, get.Code));
        Assert.Equal(2, sleeps.Count);
        var post = await Assert.ThrowsAsync<FpCheckerApiException>(() => client.CheckQuotaAsync(new { }));
        Assert.Equal((0, "network_error"), (post.Status, post.Code));
        Assert.Equal(2, sleeps.Count);
    }

    // --- validation ---

    [Theory]
    [InlineData("http://api.example.com")]
    [InlineData("not a url")]
    [InlineData("ftp://x.test")]
    [InlineData("https://")]
    [InlineData("")]
    public void BaseUrlRejected(string bad) =>
        Assert.Throws<ArgumentException>(() => new FpChecker(new FpCheckerOptions { SecretKey = SK, BaseUrl = bad }));

    [Theory]
    [InlineData("http://localhost:8787")]
    [InlineData("http://127.0.0.1:1")]
    [InlineData("http://[::1]:2")]
    [InlineData("https://x.test")]
    public void BaseUrlAccepted(string ok)
    {
        using var c = new FpChecker(new FpCheckerOptions { SecretKey = SK, BaseUrl = ok });
    }

    [Fact]
    public void InvalidTimeoutRejected()
    {
        foreach (var t in new[] { TimeSpan.Zero, TimeSpan.FromSeconds(-1), System.Threading.Timeout.InfiniteTimeSpan, TimeSpan.MaxValue })
        {
            Assert.Throws<ArgumentException>(() => new FpChecker(new FpCheckerOptions { SecretKey = SK, Timeout = t }));
        }
    }

    [Theory]
    [InlineData("sk\r\nX: y")]
    [InlineData("sk\n")]
    [InlineData("sk\0")]
    [InlineData("sk\u007f")]
    [InlineData("s k\t")]
    [InlineData("ské")]
    public void KeysWithControlOrNonAsciiRejected(string bad)
    {
        Assert.Throws<ArgumentException>(() => new FpChecker(new FpCheckerOptions { SecretKey = bad }));
        Assert.Throws<ArgumentException>(() => new FpChecker(new FpCheckerOptions { SecretKey = SK, PublishableKey = bad }));
    }

    [Fact]
    public void ValidationMessagesNeverContainKey()
    {
        var e = Assert.Throws<ArgumentException>(() => new FpChecker(new FpCheckerOptions { SecretKey = "sk_secret\r\nX: y" }));
        Assert.DoesNotContain("sk_secret", e.Message + e);
    }

    [Fact]
    public void EmptyPublishableKeyRejectedButNullOk()
    {
        using var c = new FpChecker(new FpCheckerOptions { SecretKey = SK, PublishableKey = null });
        Assert.Throws<ArgumentException>(() => new FpChecker(new FpCheckerOptions { SecretKey = SK, PublishableKey = "" }));
    }

    [Fact]
    public async Task DisposedClientRefusesCalls()
    {
        var (client, handler, _) = Mk(R(Resp(200, new { })));
        client.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { _ = client.GetHealthAsync(); });
        client.Dispose(); // idempotent
        Assert.Empty(handler.Calls);
        await Task.CompletedTask;
    }

    private sealed class Unserializable
    {
        public int Boom => throw new InvalidOperationException("sk_test_123 inside");
    }

    [Fact]
    public void UnserializableBodyThrowsSynchronouslyWithoutRequest()
    {
        var (client, handler, _) = Mk(R(Resp(200, new { })));
        var e = Assert.Throws<ArgumentException>(() => { _ = client.CheckQuotaAsync(new Unserializable()); });
        Assert.DoesNotContain(SK, e.Message + e);
        Assert.Empty(handler.Calls);
    }

    [Fact]
    public void NullBotCheckHeadersThrowSynchronously()
    {
        var (client, _, _) = Mk(R());
        Assert.Throws<ArgumentNullException>(() => { _ = client.BotCheckAsync("GET", "https://x.test/", "1.1.1.1", null!); });
    }

    // --- D1: the whole handler chain is checked ---

    private sealed class PassThrough : DelegatingHandler
    {
        public PassThrough(HttpMessageHandler? inner = null)
        {
            if (inner is not null)
            {
                InnerHandler = inner;
            }
        }
    }

    [Fact]
    public void DelegatingWrapperAroundRedirectFollowingHandlerRejected()
    {
        var opts = new FpCheckerOptions { SecretKey = SK };
        var e1 = Assert.Throws<ArgumentException>(() => new FpChecker(opts, new PassThrough(new HttpClientHandler())));
        Assert.Throws<ArgumentException>(() => new FpChecker(opts, new PassThrough(new SocketsHttpHandler())));
        Assert.Throws<ArgumentException>(() => new FpChecker(opts, new PassThrough(new PassThrough(new HttpClientHandler()))));
        Assert.DoesNotContain(SK, e1.Message + e1);
    }

    [Fact]
    public void DelegatingWrapperAroundRedirectFreeHandlerAccepted()
    {
        var opts = new FpCheckerOptions { SecretKey = SK };
        using var a = new FpChecker(opts, new PassThrough(new SocketsHttpHandler { AllowAutoRedirect = false }));
        using var b = new FpChecker(opts, new PassThrough(new PassThrough(new HttpClientHandler { AllowAutoRedirect = false })));
        using var c = new FpChecker(opts, new PassThrough(new FakeHandler()));
        using var d = new FpChecker(opts, new PassThrough()); // chain ends in null: nothing to check
    }

    [Fact]
    public void OptionsSecretKeyIsNotSerialised()
    {
        var opts = new FpCheckerOptions { SecretKey = "sk_live_serialise_me_not" };
        var json = System.Text.Json.JsonSerializer.Serialize(opts);
        Assert.DoesNotContain("sk_live_serialise_me_not", json);
    }
}
