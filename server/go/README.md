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

```go
res, err := fpchecker.UnsealResult(blob, []string{activeKey, previousKey})
err = fpchecker.VerifyWebhookSignature(rawBody, r.Header.Get("FPC-Signature"), secret, 5*time.Minute, time.Now())
```

`UnsealResult` returns `*SealedResultError` and `VerifyWebhookSignature` returns `*WebhookSignatureError`; both carry a language-neutral `Code`. Pass the exact raw request bytes to the webhook verifier.
