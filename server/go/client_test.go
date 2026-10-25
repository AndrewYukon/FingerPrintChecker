package fpchecker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testSecret = "sk_test_SECRET_VALUE_123"
const testPub = "pk_test_PUBLIC_456"

type seen struct {
	Method, EscapedPath, Secret, Pub string
	HasSecret, HasPub                bool
	Body                             string
}

type recorder struct {
	mu    sync.Mutex
	reqs  []seen
	serve http.HandlerFunc
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	buf := new(strings.Builder)
	b := make([]byte, 4096)
	for {
		n, err := req.Body.Read(b)
		buf.Write(b[:n])
		if err != nil {
			break
		}
	}
	r.mu.Lock()
	r.reqs = append(r.reqs, seen{
		Method: req.Method, EscapedPath: req.URL.EscapedPath(),
		Secret: req.Header.Get("X-Secret-Key"), HasSecret: req.Header.Values("X-Secret-Key") != nil,
		Pub: req.Header.Get("X-Publishable-Key"), HasPub: req.Header.Values("X-Publishable-Key") != nil,
		Body: buf.String(),
	})
	r.mu.Unlock()
	if r.serve != nil {
		r.serve(w, req)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

func newTestClient(t *testing.T, h http.Handler, opts ...Option) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	all := append([]Option{WithBaseURL(ts.URL), WithPublishableKey(testPub), WithSleep(func(context.Context, time.Duration) error { return nil })}, opts...)
	c, err := New(testSecret, all...)
	if err != nil {
		t.Fatal(err)
	}
	return c, ts
}

type specOp struct {
	OperationID string                `json:"operationId"`
	Security    []map[string][]string `json:"security"`
}

type apiSpec struct {
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

// ops returns path -> verb -> operation, skipping non-verb keys such as "parameters".
func (s apiSpec) ops(t *testing.T) map[string]map[string]specOp {
	out := map[string]map[string]specOp{}
	for p, m := range s.Paths {
		out[p] = map[string]specOp{}
		for k, raw := range m {
			switch k {
			case "get", "post", "put", "patch", "delete", "head", "options":
				var op specOp
				if err := json.Unmarshal(raw, &op); err != nil {
					t.Fatal(err)
				}
				out[p][k] = op
			}
		}
	}
	return out
}

func pascal(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

func TestEveryOperationHasMethod(t *testing.T) {
	var spec apiSpec
	raw, err := os.ReadFile("../../openapi/fpchecker-api.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	ct := reflect.TypeOf(&Client{})
	n := 0
	for _, methods := range spec.ops(t) {
		for _, op := range methods {
			if op.OperationID == "" {
				continue
			}
			n++
			if _, ok := ct.MethodByName(pascal(op.OperationID)); !ok {
				t.Errorf("no method for operationId %s", op.OperationID)
			}
		}
	}
	if n != 17 {
		t.Fatalf("expected 17 operations, found %d", n)
	}
}

func TestOperationsHitSpecRoute(t *testing.T) {
	var spec apiSpec
	raw, _ := os.ReadFile("../../openapi/fpchecker-api.json")
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	const id = "a/b c?d%e"
	ctx := context.Background()
	calls := map[string]func(*Client) (json.RawMessage, error){
		"createIntent":       func(c *Client) (json.RawMessage, error) { return c.CreateIntent(ctx, map[string]any{"a": 1}) },
		"getChallenge":       func(c *Client) (json.RawMessage, error) { return c.GetChallenge(ctx, Query{"intent": "x"}) },
		"identify":           func(c *Client) (json.RawMessage, error) { return c.Identify(ctx, map[string]any{"a": 1}) },
		"checkEligibility":   func(c *Client) (json.RawMessage, error) { return c.CheckEligibility(ctx, map[string]any{}) },
		"releaseEligibility": func(c *Client) (json.RawMessage, error) { return c.ReleaseEligibility(ctx, map[string]any{}) },
		"checkQuota":         func(c *Client) (json.RawMessage, error) { return c.CheckQuota(ctx, map[string]any{}) },
		"bindSubject":        func(c *Client) (json.RawMessage, error) { return c.BindSubject(ctx, map[string]any{}) },
		"relateSubjects":     func(c *Client) (json.RawMessage, error) { return c.RelateSubjects(ctx, map[string]any{}) },
		"sendFeedback":       func(c *Client) (json.RawMessage, error) { return c.SendFeedback(ctx, map[string]any{}) },
		"getClaimFlags":      func(c *Client) (json.RawMessage, error) { return c.GetClaimFlags(ctx, nil) },
		"searchEvents":       func(c *Client) (json.RawMessage, error) { return c.SearchEvents(ctx, nil) },
		"getEvent":           func(c *Client) (json.RawMessage, error) { return c.GetEvent(ctx, id) },
		"updateEvent":        func(c *Client) (json.RawMessage, error) { return c.UpdateEvent(ctx, id, map[string]any{"a": 1}) },
		"getVisitor":         func(c *Client) (json.RawMessage, error) { return c.GetVisitor(ctx, id) },
		"deleteVisitor":      func(c *Client) (json.RawMessage, error) { return c.DeleteVisitor(ctx, id) },
		"getHealth":          func(c *Client) (json.RawMessage, error) { return c.GetHealth(ctx) },
		"getStatus":          func(c *Client) (json.RawMessage, error) { return c.GetStatus(ctx) },
	}
	rows := 0
	for path, methods := range spec.ops(t) {
		for verb, op := range methods {
			if op.OperationID == "" {
				continue
			}
			rows++
			path, verb, op := path, verb, op
			t.Run(op.OperationID, func(t *testing.T) {
				call, ok := calls[op.OperationID]
				if !ok {
					t.Fatalf("no test call for %s", op.OperationID)
				}
				rec := &recorder{}
				c, _ := newTestClient(t, rec)
				if _, err := call(c); err != nil {
					t.Fatal(err)
				}
				if rec.count() != 1 {
					t.Fatalf("want 1 request, got %d", rec.count())
				}
				got := rec.reqs[0]
				wantPath := strings.NewReplacer("{eventId}", url.PathEscape(id), "{visitorId}", url.PathEscape(id)).Replace(path)
				if got.Method != strings.ToUpper(verb) || got.EscapedPath != wantPath {
					t.Fatalf("got %s %s want %s %s", got.Method, got.EscapedPath, strings.ToUpper(verb), wantPath)
				}
				wantSecret, wantPub := false, false
				for _, sec := range op.Security {
					if _, ok := sec["secretKey"]; ok {
						wantSecret = true
					}
					if _, ok := sec["publishableKey"]; ok {
						wantPub = true
					}
				}
				if got.HasSecret != wantSecret || got.HasPub != wantPub {
					t.Fatalf("auth headers secret=%v pub=%v want %v %v", got.HasSecret, got.HasPub, wantSecret, wantPub)
				}
				if wantSecret && got.Secret != testSecret || wantPub && got.Pub != testPub {
					t.Fatal("wrong key value")
				}
			})
		}
	}
	if rows != 17 || len(calls) != 17 {
		t.Fatalf("rows=%d calls=%d", rows, len(calls))
	}
}

func TestQueryEncoding(t *testing.T) {
	var gotQuery string
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) { gotQuery = r.URL.RawQuery; _, _ = w.Write([]byte(`{}`)) }}
	c, _ := newTestClient(t, rec)
	_, err := c.SearchEvents(context.Background(), Query{"visitorId": "a b&c", "bot": true, "limit": 5, "skip": nil})
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "bot=true&limit=5&visitorId=a+b%26c" {
		t.Fatal(gotQuery)
	}
}

func TestPublishableKeyRequired(t *testing.T) {
	rec := &recorder{}
	ts := httptest.NewServer(rec)
	defer ts.Close()
	c, err := New(testSecret, WithBaseURL(ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Identify(context.Background(), map[string]any{}); err == nil {
		t.Fatal("want error")
	}
	if _, err := c.GetChallenge(context.Background(), Query{}); err == nil {
		t.Fatal("want error")
	}
	if rec.count() != 0 {
		t.Fatal("request must not be sent")
	}
}

func TestNewValidation(t *testing.T) {
	bad := map[string][]Option{
		"http remote":    {WithBaseURL("http://example.com")},
		"ftp":            {WithBaseURL("ftp://localhost")},
		"no host":        {WithBaseURL("https://")},
		"userinfo":       {WithBaseURL("https://u:p@example.com")},
		"zero timeout":   {WithTimeout(0)},
		"neg timeout":    {WithTimeout(-time.Second)},
		"bad pub":        {WithPublishableKey("pk\nx")},
		"empty pub":      {WithPublishableKey("")},
		"nil http":       {WithHTTPClient(nil)},
		"http lookalike": {WithBaseURL("http://localhost.evil.com")},
	}
	for name, opts := range bad {
		if _, err := New(testSecret, opts...); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	for _, s := range []string{"", "sk\n", "sk\x7f", "ské"} {
		_, err := New(s)
		if err == nil {
			t.Errorf("secret %q must be rejected", s)
		} else if s != "" && strings.Contains(err.Error(), s) {
			t.Errorf("error echoes secret")
		}
	}
	for _, u := range []string{"http://localhost:8080", "http://127.0.0.1:1", "http://[::1]:80", "https://example.com/", "https://example.com/base/"} {
		if _, err := New(testSecret, WithBaseURL(u)); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	if c, err := New(testSecret); err != nil || c.cfg.baseURL != "https://api.fpchecker.com" || c.cfg.timeout != 10*time.Second {
		t.Fatalf("defaults wrong: %v", err)
	}
}

func TestSecretNeverLeaks(t *testing.T) {
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"bad_request_` + testSecret + `"}`))
	}}
	c, _ := newTestClient(t, rec)
	_, err := c.CheckQuota(context.Background(), map[string]any{})
	outputs := []string{
		fmt.Sprintf("%v|%+v|%#v|%s|%q", c, c, c, c, c),
		fmt.Sprintf("%v|%+v|%#v", *c, *c, *c),
		fmt.Sprint(err), fmt.Sprintf("%+v|%#v", err, err),
	}
	for i, o := range outputs {
		if strings.Contains(o, testSecret) {
			t.Errorf("output %d leaks secret: %s", i, o)
		}
	}
	if rec.reqs[0].EscapedPath != "/v1/quota" {
		t.Fatal("secret must not be in URL")
	}
	// network error text
	dead := httptest.NewServer(http.NotFoundHandler())
	u := dead.URL
	dead.Close()
	c2, _ := New(testSecret, WithBaseURL(u), WithSleep(func(context.Context, time.Duration) error { return nil }))
	_, err = c2.GetHealth(context.Background())
	if err == nil || strings.Contains(err.Error(), testSecret) || strings.Contains(fmt.Sprintf("%+v", errors.Unwrap(err)), testSecret) {
		t.Fatalf("network err: %v", err)
	}
}

func TestAPIErrorCodes(t *testing.T) {
	cases := []struct {
		body, code string
		status     int
	}{
		{`{"error":"quota_exceeded","reason":"r"}`, "quota_exceeded", 402},
		{`{"reason":"only_reason"}`, "only_reason", 403},
		{`{"error":5}`, "", 400},
		{`not json`, "", 400},
		{``, "", 404},
		{`["x"]`, "", 400},
	}
	for _, tc := range cases {
		tc := tc
		rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}}
		c, _ := newTestClient(t, rec)
		_, err := c.SendFeedback(context.Background(), map[string]any{})
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != tc.status || ae.Code != tc.code || string(ae.Body) != tc.body {
			t.Errorf("%q: got %+v", tc.body, ae)
		}
	}
}

func TestOkFalseIs2xxData(t *testing.T) {
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"ok":false,"reason":"denied"}`)) }}
	c, _ := newTestClient(t, rec)
	out, err := c.CheckEligibility(context.Background(), map[string]any{})
	if err != nil || string(out) != `{"ok":false,"reason":"denied"}` {
		t.Fatalf("%s %v", out, err)
	}
	rec2 := &recorder{serve: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }}
	c2, _ := newTestClient(t, rec2)
	out, err = c2.DeleteVisitor(context.Background(), "v")
	if err != nil || string(out) != "{}" {
		t.Fatalf("%s %v", out, err)
	}
}

func TestRetryGETOn503WithRetryAfter(t *testing.T) {
	var n int32
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}}
	var sleeps []time.Duration
	c, _ := newTestClient(t, rec, WithSleep(func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }))
	if _, err := c.GetVisitor(context.Background(), "v"); err != nil {
		t.Fatal(err)
	}
	if rec.count() != 3 || len(sleeps) != 2 || sleeps[0] != 3*time.Second {
		t.Fatalf("reqs=%d sleeps=%v", rec.count(), sleeps)
	}
}

func TestRetryGivesUpAfterTwoAndCapsDelay(t *testing.T) {
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "999")
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
	}}
	var sleeps []time.Duration
	c, _ := newTestClient(t, rec, WithSleep(func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }))
	_, err := c.GetHealth(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 429 || ae.Code != "rate_limited" || ae.RetryAfter == nil || *ae.RetryAfter != 999 {
		t.Fatalf("%+v", ae)
	}
	if rec.count() != 3 || sleeps[0] != 10*time.Second || sleeps[1] != 10*time.Second {
		t.Fatalf("reqs=%d sleeps=%v", rec.count(), sleeps)
	}
}

func TestNonGETNeverRetried(t *testing.T) {
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }}
	c, _ := newTestClient(t, rec)
	ctx := context.Background()
	for _, f := range []func() error{
		func() error { _, e := c.CreateIntent(ctx, map[string]any{}); return e },
		func() error { _, e := c.UpdateEvent(ctx, "e", map[string]any{}); return e },
		func() error { _, e := c.DeleteVisitor(ctx, "v"); return e },
	} {
		before := rec.count()
		if err := f(); err == nil {
			t.Fatal("want error")
		}
		if rec.count()-before != 1 {
			t.Fatalf("retried: %d", rec.count()-before)
		}
	}
}

func TestNetworkErrorGETRetriedPOSTNot(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	u := dead.URL
	dead.Close()
	var sleeps int
	c, _ := New(testSecret, WithBaseURL(u), WithSleep(func(context.Context, time.Duration) error { sleeps++; return nil }))
	_, err := c.GetHealth(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 0 || ae.Code != "network_error" || ae.Unwrap() == nil || sleeps != 2 {
		t.Fatalf("%v sleeps=%d", err, sleeps)
	}
	sleeps = 0
	_, err = c.CheckQuota(context.Background(), map[string]any{})
	if !errors.As(err, &ae) || ae.Code != "network_error" || sleeps != 0 {
		t.Fatalf("%v sleeps=%d", err, sleeps)
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}}
	c, ts := newTestClient(t, rec, WithTimeout(50*time.Millisecond))
	defer close(release)
	_ = ts
	_, err := c.CheckQuota(context.Background(), map[string]any{})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 0 || ae.Code != "timeout" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func TestContextCancelStopsRetries(t *testing.T) {
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }}
	ctx, cancel := context.WithCancel(context.Background())
	c, _ := newTestClient(t, rec, WithSleep(func(ctx context.Context, d time.Duration) error { cancel(); return ctx.Err() }))
	_, err := c.GetHealth(ctx)
	if err == nil || rec.count() != 1 {
		t.Fatalf("err=%v reqs=%d", err, rec.count())
	}
	// already-cancelled ctx: no retry, error wraps context.Canceled
	rec2 := &recorder{}
	c2, _ := newTestClient(t, rec2)
	_, err = c2.GetHealth(ctx)
	var ae *APIError
	if !errors.As(err, &ae) || !errors.Is(err, context.Canceled) || ae.Code != "network_error" || rec2.count() != 0 {
		t.Fatalf("%v", err)
	}
}

func TestRedirectNeverFollowedEvenWithCustomClient(t *testing.T) {
	for _, code := range []int{302, 307} {
		other := &recorder{}
		ots := httptest.NewServer(other)
		defer ots.Close()
		rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, ots.URL+"/steal", code)
		}}
		own := &http.Client{}
		c, _ := newTestClient(t, rec, WithHTTPClient(own))
		for _, f := range []func() error{
			func() error { _, e := c.CheckQuota(context.Background(), map[string]any{}); return e },
			func() error { _, e := c.GetVisitor(context.Background(), "v"); return e },
		} {
			err := f()
			var ae *APIError
			if !errors.As(err, &ae) || ae.Status != code {
				t.Fatalf("code %d: %v", code, err)
			}
		}
		if other.count() != 0 {
			t.Fatalf("redirect target received %d requests", other.count())
		}
		if own.CheckRedirect != nil {
			t.Fatal("caller's client was mutated")
		}
	}
}

func TestUsesCallerTransport(t *testing.T) {
	var used int32
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&used, 1)
		return http.DefaultTransport.RoundTrip(r)
	})
	c, _ := newTestClient(t, &recorder{}, WithHTTPClient(&http.Client{Transport: rt}))
	if _, err := c.GetHealth(context.Background()); err != nil || used != 1 {
		t.Fatalf("%v %d", err, used)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRetryAfterZeroHonoured(t *testing.T) {
	var n int32
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}}
	var sleeps []time.Duration
	c, _ := newTestClient(t, rec, WithSleep(func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }))
	if _, err := c.GetHealth(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sleeps) != 1 || sleeps[0] != 0 {
		t.Fatalf("Retry-After: 0 must mean no wait, sleeps=%v", sleeps)
	}
	// absent vs zero on the error
	for hdr, want := range map[string]*int{"": nil, "0": intp(0), "7": intp(7)} {
		hdr, want := hdr, want
		rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
			if hdr != "" {
				w.Header().Set("Retry-After", hdr)
			}
			w.WriteHeader(400)
		}}
		c, _ := newTestClient(t, rec)
		_, err := c.CheckQuota(context.Background(), map[string]any{})
		var ae *APIError
		if !errors.As(err, &ae) || (ae.RetryAfter == nil) != (want == nil) || (want != nil && *ae.RetryAfter != *want) {
			t.Fatalf("hdr %q: %+v", hdr, ae)
		}
	}
}

func intp(n int) *int { return &n }

func TestDefaultSleepReturnsPromptlyWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := sleepCtx(ctx, 10*time.Second)
	if !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
	// through the client with the default sleep: 503 then cancelled ctx, no 10s wait
	ctx2, cancel2 := context.WithCancel(context.Background())
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(503)
		time.AfterFunc(100*time.Millisecond, cancel2) // fires while the client sits in its 10s back-off
	}}
	ts := httptest.NewServer(rec)
	defer ts.Close()
	c, _ := New(testSecret, WithBaseURL(ts.URL))
	start = time.Now()
	_, err = c.GetHealth(ctx2)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 503 || time.Since(start) > 2*time.Second || rec.count() != 1 {
		t.Fatalf("err=%v after %v reqs=%d", err, time.Since(start), rec.count())
	}
}

func TestBodyRedactedToo(t *testing.T) {
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"x","echo":"` + testSecret + `"}`))
	}}
	c, _ := newTestClient(t, rec)
	_, err := c.CheckQuota(context.Background(), map[string]any{})
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatal(err)
	}
	if strings.Contains(string(ae.Body), testSecret) || strings.Contains(ae.Error(), testSecret) || !strings.Contains(string(ae.Body), "[redacted]") {
		t.Fatalf("body=%s err=%s", ae.Body, ae.Error())
	}
	if ae.Code != "x" {
		t.Fatal(ae.Code)
	}
}

func TestBaseURLRejectsQueryAndFragment(t *testing.T) {
	for _, u := range []string{"https://example.com?a=1", "https://example.com/x#f", "https://example.com/?", "https://example.com#"} {
		if _, err := New(testSecret, WithBaseURL(u)); err == nil {
			t.Errorf("%s must be rejected", u)
		}
	}
}
