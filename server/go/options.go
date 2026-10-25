package fpchecker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the production API origin.
const DefaultBaseURL = "https://api.fpchecker.com"

const (
	defaultTimeout = 10 * time.Second
	userAgent      = "fpchecker-go/0.1.0"
)

type config struct {
	secretKey      string
	publishableKey string
	baseURL        string
	timeout        time.Duration
	httpClient     *http.Client
	sleep          func(context.Context, time.Duration) error
}

// Option configures a Client. Options return an error from New when invalid.
type Option func(*config) error

// WithBaseURL sets the API origin. It must be https, except http for localhost, 127.0.0.1 and [::1].
func WithBaseURL(raw string) Option {
	return func(c *config) error {
		u, err := validateBaseURL(raw)
		if err != nil {
			return err
		}
		c.baseURL = u
		return nil
	}
}

// WithHTTPClient supplies the transport. The client is copied, never mutated:
// the copy refuses to follow redirects so a 3xx cannot carry the key elsewhere.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *config) error {
		if hc == nil {
			return errors.New("fpchecker: HTTP client must not be nil")
		}
		c.httpClient = hc
		return nil
	}
}

// WithPublishableKey sets the pk_ key used by Identify and GetChallenge.
func WithPublishableKey(key string) Option {
	return func(c *config) error {
		if err := checkHeaderValue("publishable key", key); err != nil {
			return err
		}
		c.publishableKey = key
		return nil
	}
}

// WithTimeout sets the per-attempt request timeout (default 10s); must be > 0.
func WithTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return errors.New("fpchecker: timeout must be > 0")
		}
		c.timeout = d
		return nil
	}
}

// WithSleep replaces the retry back-off sleep (a test seam). It must return
// ctx.Err() if the context ends first.
func WithSleep(fn func(context.Context, time.Duration) error) Option {
	return func(c *config) error {
		if fn == nil {
			return errors.New("fpchecker: sleep func must not be nil")
		}
		c.sleep = fn
		return nil
	}
}

func validateBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return "", errors.New("fpchecker: base URL is not a valid URL")
	}
	host := strings.ToLower(u.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return "", errors.New("fpchecker: base URL must be https (http only for localhost, 127.0.0.1, [::1])")
	}
	return strings.TrimRight(raw, "/"), nil
}

// checkHeaderValue requires non-empty printable ASCII; the value is never echoed.
func checkHeaderValue(name, v string) error {
	if v == "" {
		return fmt.Errorf("fpchecker: %s is required", name)
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return fmt.Errorf("fpchecker: %s must be printable ASCII", name)
		}
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
