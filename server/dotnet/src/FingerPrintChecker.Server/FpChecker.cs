using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace FingerPrintChecker.Server;

/// <summary>
/// Server client for the FpChecker API. The secret key goes only in the <c>X-Secret-Key</c> header. Redirects are
/// never followed. Dispose the client to release the connection pool (a handler you pass in is disposed with it).
/// </summary>
public sealed class FpChecker : IDisposable
{
    public const string DefaultBaseUrl = "https://api.fpchecker.com";

    private const int MaxRetries = 2;
    private const double MaxDelaySeconds = 10.0;
    private const string UserAgent = "fpchecker-dotnet/0.1.0";

    private readonly string _secretKey;
    private readonly string? _publishableKey;
    private readonly string _baseUrl;
    private readonly TimeSpan _timeout;
    private readonly HttpClient _http;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private int _disposed;
    private static readonly JsonElement EmptyObject = BuildEmptyObject();

    /// <summary>
    /// Creates a client. A custom <paramref name="handler"/> must not follow redirects: the whole
    /// <see cref="DelegatingHandler.InnerHandler"/> chain is walked and any <see cref="HttpClientHandler"/> or
    /// <see cref="SocketsHttpHandler"/> with <c>AllowAutoRedirect</c> on is rejected; for any other handler type the
    /// caller must guarantee it. Any 3xx that still arrives is refused.
    /// </summary>
    public FpChecker(FpCheckerOptions options, HttpMessageHandler? handler = null)
        : this(options, handler, Task.Delay)
    {
    }

    /// <summary>Test seam: inject the sleeper. Internal so callers cannot bypass anything.</summary>
    internal FpChecker(FpCheckerOptions options, HttpMessageHandler? handler, Func<TimeSpan, CancellationToken, Task> delay)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.SecretKey))
        {
            throw new ArgumentException("FpChecker: SecretKey is required", nameof(options));
        }

        CheckHeaderValue("SecretKey", options.SecretKey);
        if (options.PublishableKey is not null)
        {
            if (options.PublishableKey.Length == 0)
            {
                throw new ArgumentException("FpChecker: PublishableKey must be a non-empty string", nameof(options));
            }

            CheckHeaderValue("PublishableKey", options.PublishableKey);
        }

        if (options.Timeout <= TimeSpan.Zero || options.Timeout > TimeSpan.FromMilliseconds(int.MaxValue))
        {
            throw new ArgumentException("FpChecker: Timeout must be a positive duration", nameof(options));
        }

        var baseUrl = ValidateBaseUrl(options.BaseUrl);
        RejectRedirectFollowing(handler);

        _secretKey = options.SecretKey;
        _publishableKey = options.PublishableKey;
        _baseUrl = baseUrl;
        _timeout = options.Timeout;
        _delay = delay;
        var inner = handler ?? new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };
        _http = new HttpClient(new RedirectRefusingHandler(inner), disposeHandler: true)
        {
            Timeout = System.Threading.Timeout.InfiniteTimeSpan, // each attempt has its own linked-token timeout
        };
    }

    public override string ToString() => "FpChecker(baseUrl=" + _baseUrl + ")";

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _http.Dispose();
        }
    }

    // --- validation ---

    private static JsonElement BuildEmptyObject()
    {
        using var doc = JsonDocument.Parse("{}");
        return doc.RootElement.Clone();
    }

    private static void RejectRedirectFollowing(HttpMessageHandler? handler)
    {
        var seen = new HashSet<HttpMessageHandler>(ReferenceEqualityComparer.Instance);
        for (var h = handler; h is not null && seen.Add(h); h = (h as DelegatingHandler)?.InnerHandler)
        {
            if ((h is HttpClientHandler c && c.AllowAutoRedirect) || (h is SocketsHttpHandler s && s.AllowAutoRedirect))
            {
                throw new ArgumentException(
                    "FpChecker: the handler must not follow redirects (set AllowAutoRedirect = false)", nameof(handler));
            }
        }
    }

    private static void CheckHeaderValue(string name, string value)
    {
        foreach (var c in value)
        {
            if (c < 0x20 || c >= 0x7F)
            {
                throw new ArgumentException("FpChecker: " + name + " must be printable ASCII (no control characters)");
            }
        }
    }

    private static string ValidateBaseUrl(string? raw)
    {
        if (raw is null)
        {
            throw new ArgumentException("FpChecker: BaseUrl must be a string");
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var u) || string.IsNullOrEmpty(u.Host))
        {
            throw new ArgumentException("FpChecker: BaseUrl is not a valid URL");
        }

        var host = u.Host.ToLowerInvariant();
        var loopback = host is "localhost" or "127.0.0.1" or "[::1]" or "::1";
        var scheme = u.Scheme.ToLowerInvariant();
        if (scheme != "https" && !(scheme == "http" && loopback))
        {
            throw new ArgumentException("FpChecker: BaseUrl must be https (http only for localhost, 127.0.0.1, [::1])");
        }

        return raw.TrimEnd('/');
    }

    // --- operations (method name = operationId) ---

    public Task<JsonElement> CreateIntentAsync(object body, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/v2/intents", null, body, false, true, ct);

    public Task<JsonElement> GetChallengeAsync(IEnumerable<KeyValuePair<string, object?>> query, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Get, "/v2/challenge", query, null, true, true, ct);

    public Task<JsonElement> IdentifyAsync(object body, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/v2/identify", null, body, true, true, ct);

    public Task<JsonElement> CheckEligibilityAsync(object body, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/v1/eligibility", null, body, false, true, ct);

    public Task<JsonElement> ReleaseEligibilityAsync(object body, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/v1/eligibility/release", null, body, false, true, ct);

    /// <summary>
    /// Classify a request your backend received. Not charged, writes no event. Send <paramref name="url"/> as the
    /// visitor requested it (original host and scheme). Headers are filtered through the allowlist.
    /// </summary>
    public Task<JsonElement> BotCheckAsync(
        string method, string url, string ip, IReadOnlyDictionary<string, string> headers, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(headers);
        var body = new Dictionary<string, object?>
        {
            ["method"] = method,
            ["url"] = url,
            ["ip"] = ip,
            ["headers"] = BotHeaders.Filter(headers),
        };
        return CallAsync(HttpMethod.Post, "/v1/bot-check", null, body, false, true, ct);
    }

    public Task<JsonElement> CheckQuotaAsync(object body, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/v1/quota", null, body, false, true, ct);

    public Task<JsonElement> BindSubjectAsync(object body, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/v1/subjects/bind", null, body, false, true, ct);

    public Task<JsonElement> RelateSubjectsAsync(object body, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/v1/subjects/relation", null, body, false, true, ct);

    public Task<JsonElement> SendFeedbackAsync(object body, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/v1/feedback", null, body, false, true, ct);

    public Task<JsonElement> GetClaimFlagsAsync(IEnumerable<KeyValuePair<string, object?>>? query = null, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Get, "/v1/claims/flags", query, null, false, true, ct);

    public Task<JsonElement> SearchEventsAsync(IEnumerable<KeyValuePair<string, object?>>? query = null, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Get, "/v1/events", query, null, false, true, ct);

    public Task<JsonElement> GetEventAsync(string eventId, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Get, "/v1/events/" + PathId(eventId), null, null, false, true, ct);

    public Task<JsonElement> UpdateEventAsync(string eventId, object body, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Patch, "/v1/events/" + PathId(eventId), null, body, false, true, ct);

    public Task<JsonElement> GetVisitorAsync(string visitorId, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Get, "/v1/visitors/" + PathId(visitorId), null, null, false, true, ct);

    public Task<JsonElement> DeleteVisitorAsync(string visitorId, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Delete, "/v1/visitors/" + PathId(visitorId), null, null, false, true, ct);

    public Task<JsonElement> GetHealthAsync(CancellationToken ct = default) =>
        CallAsync(HttpMethod.Get, "/health", null, null, false, false, ct);

    public Task<JsonElement> GetStatusAsync(CancellationToken ct = default) =>
        CallAsync(HttpMethod.Get, "/status", null, null, false, false, ct);

    // --- encoding ---

    /// <summary>quote(value, safe="") for a path segment; ids that could change the route are refused.</summary>
    private static string PathId(string? id)
    {
        if (string.IsNullOrEmpty(id) || id == "." || id == "..")
        {
            throw new ArgumentException("FpChecker: id must be a non-empty string and not '.' or '..'");
        }

        return Encode(id, false);
    }

    /// <summary>Python quote / quote_plus with safe="": unreserved is A-Za-z0-9 and _.-~</summary>
    internal static string Encode(string value, bool plus)
    {
        var sb = new StringBuilder();
        foreach (int c in Encoding.UTF8.GetBytes(value))
        {
            var unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '_' || c == '.' || c == '-' || c == '~';
            if (unreserved)
            {
                sb.Append((char)c);
            }
            else if (plus && c == ' ')
            {
                sb.Append('+');
            }
            else
            {
                sb.Append('%').Append(c.ToString("X2", CultureInfo.InvariantCulture));
            }
        }

        return sb.ToString();
    }

    internal static string QueryString(IEnumerable<KeyValuePair<string, object?>>? query)
    {
        if (query is null)
        {
            return string.Empty;
        }

        var sb = new StringBuilder();
        foreach (var (k, v) in query)
        {
            if (v is null)
            {
                continue;
            }

            var s = v switch
            {
                bool b => b ? "true" : "false",
                IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
                _ => v.ToString() ?? string.Empty,
            };
            sb.Append(sb.Length == 0 ? '?' : '&').Append(Encode(k, true)).Append('=').Append(Encode(s, true));
        }

        return sb.ToString();
    }

    // --- response parsing ---

    private static JsonElement? ParseJson(byte[] raw)
    {
        if (raw.Length == 0)
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(raw);
            return doc.RootElement.ValueKind == JsonValueKind.Null ? null : doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? ErrorCode(JsonElement? body)
    {
        if (body is not { ValueKind: JsonValueKind.Object } obj)
        {
            return null;
        }

        if (!obj.TryGetProperty("error", out var code) || code.ValueKind == JsonValueKind.Null)
        {
            obj.TryGetProperty("reason", out code);
        }

        return code.ValueKind == JsonValueKind.String ? code.GetString() : null;
    }

    private static int? ParseRetryAfter(string? value)
    {
        var v = value?.Trim();
        if (v is null || v.Length < 1 || v.Length > 9 || !v.All(c => c >= '0' && c <= '9'))
        {
            return null;
        }

        return int.Parse(v, CultureInfo.InvariantCulture);
    }

    private static bool IsTimeout(Exception e)
    {
        for (Exception? c = e; c is not null; c = c.InnerException)
        {
            if (c is TimeoutException || (c is SocketException { SocketErrorCode: SocketError.TimedOut }))
            {
                return true;
            }
        }

        return false;
    }

    // --- transport ---

    private sealed record Attempt(string? FailureCode, int Status, byte[] Raw, string? RetryAfter);

    private async Task<Attempt> AttemptAsync(
        HttpMethod method, string url, IReadOnlyList<(string, string)> headers, byte[]? data, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeout);
        try
        {
            using var req = new HttpRequestMessage(method, new Uri(url, UriKind.Absolute));
            foreach (var (k, v) in headers)
            {
                req.Headers.TryAddWithoutValidation(k, v);
            }

            if (data is not null)
            {
                req.Content = new ByteArrayContent(data);
                req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }

            using var res = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            var status = (int)res.StatusCode;
            if (status >= 300 && status < 400)
            {
                return new Attempt("network_error", status, Array.Empty<byte>(), null);
            }

            string? retryAfter = null;
            if (res.Headers.NonValidated.TryGetValues("Retry-After", out var ra))
            {
                retryAfter = ra.ToString();
            }

            var raw = res.Content is null ? Array.Empty<byte>() : await res.Content.ReadAsByteArrayAsync(cts.Token).ConfigureAwait(false);
            return new Attempt(null, status, raw, retryAfter);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new Attempt("timeout", 0, Array.Empty<byte>(), null);
        }
        catch (FpCheckerApiException e)
        {
            return new Attempt(e.Code ?? "network_error", 0, Array.Empty<byte>(), null);
        }
        catch (Exception e)
        {
            // Never keep or surface e: HttpRequestException and header validation messages can echo header values.
            return new Attempt(IsTimeout(e) ? "timeout" : "network_error", 0, Array.Empty<byte>(), null);
        }
    }

    /// <summary>Validates and builds the request synchronously (argument errors throw here, never as a faulted Task).</summary>
    private Task<JsonElement> CallAsync(
        HttpMethod method, string path, IEnumerable<KeyValuePair<string, object?>>? query, object? body,
        bool publishable, bool auth, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var url = _baseUrl + path + QueryString(query);
        var headers = new List<(string, string)> { ("Accept", "application/json"), ("User-Agent", UserAgent) };
        if (publishable)
        {
            if (string.IsNullOrEmpty(_publishableKey))
            {
                throw new InvalidOperationException("FpChecker: PublishableKey is required for this operation");
            }

            headers.Add(("X-Publishable-Key", _publishableKey));
        }
        else if (auth)
        {
            headers.Add(("X-Secret-Key", _secretKey));
        }

        byte[]? data = null;
        if (body is not null)
        {
            try
            {
                data = JsonSerializer.SerializeToUtf8Bytes(body);
            }
            catch (Exception e) when (e is NotSupportedException or InvalidOperationException or JsonException)
            {
                throw new ArgumentException("FpChecker: body is not JSON-serializable", nameof(body));
            }
        }

        return ExecuteAsync(method, url, headers, data, ct);
    }

    private async Task<JsonElement> ExecuteAsync(
        HttpMethod method, string url, IReadOnlyList<(string, string)> headers, byte[]? data, CancellationToken ct)
    {
        var maxRetries = method == HttpMethod.Get ? MaxRetries : 0;
        var attempt = 0;
        while (true)
        {
            var a = await AttemptAsync(method, url, headers, data, ct).ConfigureAwait(false);
            if (a.FailureCode is not null)
            {
                if (attempt < maxRetries)
                {
                    await _delay(TimeSpan.FromSeconds(Math.Min(0.5 * (1 << attempt), MaxDelaySeconds)), ct).ConfigureAwait(false);
                    attempt++;
                    continue;
                }

                throw new FpCheckerApiException(0, a.FailureCode);
            }

            var parsed = ParseJson(a.Raw);
            if (a.Status >= 200 && a.Status < 300)
            {
                return parsed ?? EmptyObject;
            }

            var retryAfter = ParseRetryAfter(a.RetryAfter);
            if ((a.Status == 429 || a.Status >= 500) && attempt < maxRetries)
            {
                double wait = retryAfter ?? 0.5 * (1 << attempt);
                await _delay(TimeSpan.FromSeconds(Math.Min(wait, MaxDelaySeconds)), ct).ConfigureAwait(false);
                attempt++;
                continue;
            }

            throw new FpCheckerApiException(a.Status, ErrorCode(parsed), retryAfter, parsed);
        }
    }
}
