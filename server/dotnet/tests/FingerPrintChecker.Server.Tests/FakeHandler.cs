using System.Net;
using System.Text;

namespace FingerPrintChecker.Server.Tests;

internal sealed record Call(string Method, string Url, IReadOnlyDictionary<string, string> Headers, byte[]? Body)
{
    public string? Header(string name) =>
        Headers.FirstOrDefault(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Value;

    public string Path
    {
        get
        {
            var rest = Url.Substring(Url.IndexOf("://", StringComparison.Ordinal) + 3);
            rest = rest.Substring(rest.IndexOf('/'));
            var q = rest.IndexOf('?');
            return q < 0 ? rest : rest.Substring(0, q);
        }
    }
}

/// <summary>Replays queued responses (or throws queued exceptions) and records every request.</summary>
internal sealed class FakeHandler : HttpMessageHandler
{
    private readonly Queue<object> _queue = new();
    public List<Call> Calls { get; } = new();

    public FakeHandler(params object[] responses)
    {
        foreach (var r in responses)
        {
            _queue.Enqueue(r);
        }
    }

    public static Func<HttpResponseMessage> Resp(int status, object? body = null, params (string, string)[] headers) => () =>
    {
        var msg = new HttpResponseMessage((HttpStatusCode)status);
        if (body is not null)
        {
            var raw = body is byte[] b ? b : Encoding.UTF8.GetBytes(body is string s ? s : System.Text.Json.JsonSerializer.Serialize(body));
            msg.Content = new ByteArrayContent(raw);
        }

        foreach (var (k, v) in headers)
        {
            msg.Headers.TryAddWithoutValidation(k, v);
        }

        return msg;
    };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string>();
        foreach (var h in request.Headers)
        {
            headers[h.Key] = string.Join(",", h.Value);
        }

        byte[]? body = null;
        if (request.Content is not null)
        {
            body = await request.Content.ReadAsByteArrayAsync(cancellationToken);
            foreach (var h in request.Content.Headers)
            {
                headers[h.Key] = string.Join(",", h.Value);
            }
        }

        Calls.Add(new Call(request.Method.Method, request.RequestUri!.OriginalString, headers, body));
        if (_queue.Count == 0)
        {
            throw new InvalidOperationException("no more responses");
        }

        var next = _queue.Dequeue();
        return next switch
        {
            Exception e => throw e,
            Func<HttpResponseMessage> f => f(),
            Func<CancellationToken, Task<HttpResponseMessage>> g => await g(cancellationToken),
            _ => throw new InvalidOperationException("bad fake entry"),
        };
    }
}
