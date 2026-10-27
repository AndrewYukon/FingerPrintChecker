using System.Net;
using System.Net.Sockets;
using System.Text;

namespace FingerPrintChecker.Server.Tests;

/// <summary>Real-socket HTTP/1.1 server: one connection per request, closes after answering.</summary>
internal sealed class TinyServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly Func<string, byte[]> _respond;
    private readonly CancellationTokenSource _stop = new();
    private readonly List<string> _requests = new();
    private readonly object _lock = new();

    public TinyServer(Func<string, byte[]> respond)
    {
        _respond = respond;
        _listener.Start();
        _ = Task.Run(AcceptLoop);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public string BaseUrl => "http://127.0.0.1:" + Port;

    /// <summary>Raw head (request line + headers) of every request received.</summary>
    public IReadOnlyList<string> Requests
    {
        get
        {
            lock (_lock)
            {
                return _requests.ToArray();
            }
        }
    }

    public static byte[] Raw(string s) => Encoding.ASCII.GetBytes(s);

    public static byte[] Json(int status, string reason, string body) =>
        Raw($"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}");

    private async Task AcceptLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch (Exception)
            {
                return;
            }

            _ = Task.Run(() => Serve(client));
        }
    }

    private async Task Serve(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var buf = new List<byte>();
                var one = new byte[4096];
                int headEnd;
                while ((headEnd = IndexOfHeadEnd(buf)) < 0)
                {
                    var n = await stream.ReadAsync(one, _stop.Token);
                    if (n == 0)
                    {
                        return;
                    }

                    buf.AddRange(one.AsSpan(0, n).ToArray());
                }

                var head = Encoding.ASCII.GetString(buf.GetRange(0, headEnd).ToArray());
                var length = 0;
                foreach (var line in head.Split("\r\n"))
                {
                    if (line.StartsWith("content-length:", StringComparison.OrdinalIgnoreCase))
                    {
                        length = int.Parse(line.Substring(15).Trim());
                    }
                }

                while (buf.Count < headEnd + 4 + length)
                {
                    var n = await stream.ReadAsync(one, _stop.Token);
                    if (n == 0)
                    {
                        break;
                    }

                    buf.AddRange(one.AsSpan(0, n).ToArray());
                }

                lock (_lock)
                {
                    _requests.Add(head);
                }

                await stream.WriteAsync(_respond(head), _stop.Token);
                await stream.FlushAsync(_stop.Token);
            }
            catch (Exception)
            {
                // a client that hung up is not the server's problem
            }
        }
    }

    private static int IndexOfHeadEnd(List<byte> b)
    {
        for (var i = 0; i + 3 < b.Count; i++)
        {
            if (b[i] == 13 && b[i + 1] == 10 && b[i + 2] == 13 && b[i + 3] == 10)
            {
                return i;
            }
        }

        return -1;
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        _stop.Dispose();
    }
}
