// Package fpchecker is the FingerPrintChecker server SDK: an API client, sealed
// result decryption and webhook signature verification. Standard library only.
//
// Every API method returns the 2xx response body as json.RawMessage (an empty
// body becomes {}); decode it into your own types. Non-2xx responses and
// transport failures are *APIError.
package fpchecker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxRetries   = 2
	maxDelay     = 10 * time.Second
	maxBodyBytes = 16 << 20
)

var retryAfterPattern = regexp.MustCompile(`^[0-9]{1,9}$`)

// Query holds query-string parameters; nil values are skipped.
type Query map[string]any

// Client talks to the FingerPrintChecker API. It is safe for concurrent use.
// Credentials live behind a pointer so printing a Client (even by value) never shows them.
type Client struct{ cfg *config }

// String returns a credential-free description.
func (c *Client) String() string { return fmt.Sprintf("fpchecker.Client{baseURL: %s}", c.cfg.baseURL) }

// GoString implements fmt.GoStringer without credentials.
func (c *Client) GoString() string { return c.String() }

// New builds a Client. secretKey must be non-empty printable ASCII; it is sent
// only in the X-Secret-Key header.
func New(secretKey string, opts ...Option) (*Client, error) {
	if err := checkHeaderValue("secret key", secretKey); err != nil {
		return nil, err
	}
	cfg := &config{secretKey: secretKey, baseURL: DefaultBaseURL, timeout: defaultTimeout, sleep: sleepCtx}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	hc := &http.Client{}
	if cfg.httpClient != nil {
		cp := *cfg.httpClient
		hc = &cp
	}
	hc.CheckRedirect = noRedirect
	cfg.httpClient = hc
	return &Client{cfg: cfg}, nil
}

// --- operations (method name = PascalCase operationId) ---

func (c *Client) CreateIntent(ctx context.Context, body any) (json.RawMessage, error) {
	return c.do(ctx, "POST", "/v2/intents", nil, body, authSecret)
}
func (c *Client) GetChallenge(ctx context.Context, q Query) (json.RawMessage, error) {
	return c.do(ctx, "GET", "/v2/challenge", q, nil, authPublishable)
}
func (c *Client) Identify(ctx context.Context, body any) (json.RawMessage, error) {
	return c.do(ctx, "POST", "/v2/identify", nil, body, authPublishable)
}
func (c *Client) CheckEligibility(ctx context.Context, body any) (json.RawMessage, error) {
	return c.do(ctx, "POST", "/v1/eligibility", nil, body, authSecret)
}
func (c *Client) ReleaseEligibility(ctx context.Context, body any) (json.RawMessage, error) {
	return c.do(ctx, "POST", "/v1/eligibility/release", nil, body, authSecret)
}
func (c *Client) CheckQuota(ctx context.Context, body any) (json.RawMessage, error) {
	return c.do(ctx, "POST", "/v1/quota", nil, body, authSecret)
}
func (c *Client) BindSubject(ctx context.Context, body any) (json.RawMessage, error) {
	return c.do(ctx, "POST", "/v1/subjects/bind", nil, body, authSecret)
}
func (c *Client) RelateSubjects(ctx context.Context, body any) (json.RawMessage, error) {
	return c.do(ctx, "POST", "/v1/subjects/relation", nil, body, authSecret)
}
func (c *Client) SendFeedback(ctx context.Context, body any) (json.RawMessage, error) {
	return c.do(ctx, "POST", "/v1/feedback", nil, body, authSecret)
}
func (c *Client) GetClaimFlags(ctx context.Context, q Query) (json.RawMessage, error) {
	return c.do(ctx, "GET", "/v1/claims/flags", q, nil, authSecret)
}
func (c *Client) SearchEvents(ctx context.Context, q Query) (json.RawMessage, error) {
	return c.do(ctx, "GET", "/v1/events", q, nil, authSecret)
}
func (c *Client) GetEvent(ctx context.Context, eventID string) (json.RawMessage, error) {
	return c.do(ctx, "GET", "/v1/events/"+url.PathEscape(eventID), nil, nil, authSecret)
}
func (c *Client) UpdateEvent(ctx context.Context, eventID string, body any) (json.RawMessage, error) {
	return c.do(ctx, "PATCH", "/v1/events/"+url.PathEscape(eventID), nil, body, authSecret)
}
func (c *Client) GetVisitor(ctx context.Context, visitorID string) (json.RawMessage, error) {
	return c.do(ctx, "GET", "/v1/visitors/"+url.PathEscape(visitorID), nil, nil, authSecret)
}
func (c *Client) DeleteVisitor(ctx context.Context, visitorID string) (json.RawMessage, error) {
	return c.do(ctx, "DELETE", "/v1/visitors/"+url.PathEscape(visitorID), nil, nil, authSecret)
}
func (c *Client) GetHealth(ctx context.Context) (json.RawMessage, error) {
	return c.do(ctx, "GET", "/health", nil, nil, authNone)
}
func (c *Client) GetStatus(ctx context.Context) (json.RawMessage, error) {
	return c.do(ctx, "GET", "/status", nil, nil, authNone)
}

// --- transport ---

type authKind int

const (
	authNone authKind = iota
	authSecret
	authPublishable
)

func encodeQuery(q Query) string {
	keys := make([]string, 0, len(q))
	for k, v := range q {
		if v != nil {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = url.QueryEscape(k) + "=" + url.QueryEscape(fmt.Sprint(q[k]))
	}
	return "?" + strings.Join(parts, "&")
}

func (c *Client) do(ctx context.Context, method, path string, q Query, body any, auth authKind) (json.RawMessage, error) {
	cfg := c.cfg
	if ctx == nil {
		return nil, errors.New("fpchecker: nil context")
	}
	var keyHeader, keyValue string
	switch auth {
	case authSecret:
		keyHeader, keyValue = "X-Secret-Key", cfg.secretKey
	case authPublishable:
		if cfg.publishableKey == "" {
			return nil, errors.New("fpchecker: publishable key is required for this operation (use WithPublishableKey)")
		}
		keyHeader, keyValue = "X-Publishable-Key", cfg.publishableKey
	}
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, fmt.Errorf("fpchecker: cannot encode request body: %w", err)
		}
	}
	target := cfg.baseURL + path + encodeQuery(q)
	retries := 0
	if method == "GET" {
		retries = maxRetries
	}

	for attempt := 0; ; attempt++ {
		status, hdr, raw, err := c.attempt(ctx, method, target, payload, keyHeader, keyValue)
		if err != nil {
			if attempt < retries && ctx.Err() == nil {
				if serr := cfg.sleep(ctx, backoff(attempt, nil)); serr == nil {
					continue
				}
			}
			return nil, c.transportError(ctx, err)
		}
		if status >= 200 && status < 300 {
			if len(bytes.TrimSpace(raw)) == 0 {
				return json.RawMessage("{}"), nil
			}
			return json.RawMessage(raw), nil
		}
		retryAfter := parseRetryAfter(hdr.Get("Retry-After"))
		if (status == 429 || status >= 500) && attempt < retries {
			if serr := cfg.sleep(ctx, backoff(attempt, retryAfter)); serr == nil {
				continue
			}
		}
		return nil, &APIError{
			Status:     status,
			Code:       c.redact(errorCode(raw)),
			RetryAfter: retryAfter,
			Body:       json.RawMessage(bytes.ReplaceAll(raw, []byte(cfg.secretKey), []byte("[redacted]"))),
		}
	}
}

func (c *Client) attempt(ctx context.Context, method, target string, payload []byte, keyHeader, keyValue string) (int, http.Header, []byte, error) {
	actx, cancel := context.WithTimeout(ctx, c.cfg.timeout)
	defer cancel()
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(actx, method, target, rdr)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if keyHeader != "" {
		req.Header.Set(keyHeader, keyValue)
	}
	res, err := c.cfg.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(raw) > maxBodyBytes {
		return 0, nil, nil, errors.New("response body too large")
	}
	return res.StatusCode, res.Header, raw, nil
}

func (c *Client) transportError(ctx context.Context, err error) error {
	code := "network_error"
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		code = "timeout"
	}
	return &APIError{Status: 0, Code: code, Err: err}
}

// redact keeps a server-supplied code from ever echoing the secret key.
func (c *Client) redact(s string) string {
	if s == "" {
		return s
	}
	return strings.ReplaceAll(s, c.cfg.secretKey, "[redacted]")
}

func errorCode(raw []byte) string {
	var b map[string]any
	if json.Unmarshal(raw, &b) != nil {
		return ""
	}
	if s, ok := b["error"].(string); ok {
		return s
	}
	if b["error"] == nil {
		if s, ok := b["reason"].(string); ok {
			return s
		}
	}
	return ""
}

func parseRetryAfter(v string) *int {
	v = strings.TrimSpace(v)
	if !retryAfterPattern.MatchString(v) {
		return nil
	}
	n, _ := strconv.Atoi(v)
	return &n
}

func backoff(attempt int, retryAfterSec *int) time.Duration {
	d := 500 * time.Millisecond << uint(attempt)
	if retryAfterSec != nil {
		d = time.Duration(*retryAfterSec) * time.Second
	}
	if d > maxDelay {
		d = maxDelay
	}
	return d
}
