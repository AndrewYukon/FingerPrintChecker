# fpchecker (Go)

Server SDK for FingerPrintChecker. Standard library only, Go 1.21+.

```go
c, err := fpchecker.New(os.Getenv("FPC_SECRET_KEY"),
    fpchecker.WithPublishableKey(os.Getenv("FPC_PUBLISHABLE_KEY"))) // only for Identify / GetChallenge
if err != nil { log.Fatal(err) }

out, err := c.GetVisitor(ctx, "v_123") // json.RawMessage: decode into your own type
var apiErr *fpchecker.APIError
if errors.As(err, &apiErr) { log.Println(apiErr.Status, apiErr.Code) }
```

- One method per OpenAPI operationId (PascalCase), each taking a `context.Context`. Bodies are `any` (marshalled to JSON); queries are `fpchecker.Query`.
- 2xx responses, including `{"ok": false}` refusals, are returned as `json.RawMessage` data (an empty body is `{}`). Non-2xx is `*APIError` (`Code` is the body's `error`, else `reason`). Network failures and timeouts are `*APIError` with `Status` 0 and `Code` `network_error` / `timeout`, wrapping the cause.
- Only GET is retried (429/5xx and transport errors, at most 2 retries, `Retry-After` capped at 10 s). Redirects are never followed, even with `WithHTTPClient` (your client is copied, not modified).
- The secret key travels only in `X-Secret-Key`; it never appears in URLs, errors or `%v` output.
- Options: `WithBaseURL`, `WithHTTPClient`, `WithPublishableKey`, `WithTimeout` (default 10 s), `WithSleep` (test seam).

## Bot check

`BotCheck` classifies a request your backend received (header-only: no script ran in the sender). It is not charged and writes no event. Forward the original URL (the host and scheme the visitor used, not your origin behind a CDN or load balancer) and the client IP. `BotCheckHeaders` keeps only the headers the check needs and drops Cookie, Authorization and everything else.

```go
// clientIP: behind a proxy return the address your proxy sets in a header only it can write
// (for example X-Real-IP); with no proxy, the host part of r.RemoteAddr.
var trustProxy = false // true only when every request really comes through your proxy, which sets X-Real-IP

func clientIP(r *http.Request) string {
    if v := r.Header.Get("X-Real-IP"); v != "" && trustProxy {
        return v
    }
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    return host
}

func botGate(c *fpchecker.Client, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        scheme := "http"
        if r.TLS != nil { scheme = "https" } // behind a proxy, take scheme and host from the original request
        ip := clientIP(r) // your own helper: trusted proxy header behind a proxy, else RemoteAddr
        verdict, err := c.BotCheck(r.Context(), fpchecker.BotCheckRequest{
            Method:  r.Method,
            URL:     scheme + "://" + r.Host + r.URL.RequestURI(),
            IP:      ip,
            Headers: fpchecker.BotCheckHeaders(r.Header),
        })
        if err == nil && verdict.Bot.Result == "bad" {
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r) // "good" = a verified or signed directory bot; verdict.Bot.Info says which
    })
}
```

`Bot.Result` is `good`, `bad` or `not_detected`; `Bot.Info` (`ID`, `Name`, `Provider`, `Category`, `Identity`) is set when the request named a directory bot. A 400 is an `*APIError` with `Code` `invalid_request` or `invalid_ip` and the offending `field` in `Body`. Unlike the other methods, `BotCheck` returns a typed result.

Rules of use:
- Call `BotCheck` once per request and reuse the answer; do not call it again for the same request.
- Never retry a signed request: a retry replays the signature nonce and the request is then judged `spoofed` (`bad`).
- `ip` must be the trusted client IP, not an address a client can set. Behind a proxy take it from the proxy's trusted header (for example the last `X-Forwarded-For` entry your own proxy appended), never from `RemoteAddr`, which is the proxy.
- Limits: 3,000 checks per minute per client IP and 1,200 per minute per project (429 beyond that).
- `BotCheckHeaders` also forwards any header named in the request's `signature-input`, so signed agents verify; Cookie and Authorization are never forwarded.

`ParseWebhookEvent` fills `Data.Signals.Version` (1 before server 0.48.0, 2 since) and `Data.Signals.Bot`. `SearchEvents` also filters by the `Query` keys `bot_result`, `bot_category`, `bot_identity` and `bot_id`.

```go
res, err := fpchecker.UnsealResult(blob, []string{activeKey, previousKey})
err = fpchecker.VerifyWebhookSignature(rawBody, r.Header.Get("FPC-Signature"), secret, 5*time.Minute, time.Now())
```

`UnsealResult` returns `*SealedResultError` and `VerifyWebhookSignature` returns `*WebhookSignatureError`; both carry a language-neutral `Code`. Pass the exact raw request bytes to the webhook verifier.
