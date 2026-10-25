package fpchecker

import (
	"encoding/json"
	"fmt"
)

// APIError is returned for any non-2xx API response and for transport
// failures (Status 0). 2xx bodies, including {"ok": false} refusals, are
// returned as data and never become an APIError.
type APIError struct {
	// Status is the HTTP status, or 0 for network_error / timeout.
	Status int
	// Code is the body's "error" (or, failing that, "reason") string;
	// "network_error" or "timeout" when Status is 0. Empty if the body had none.
	Code string
	// RetryAfter is the parsed Retry-After header in whole seconds; nil when
	// the header is absent or unparseable, so an explicit 0 is distinguishable.
	RetryAfter *int
	// Body is the raw response body (may be empty or not JSON), with the secret key redacted.
	Body json.RawMessage
	// Err is the underlying cause for Status 0; see Unwrap.
	Err error
}

// Error implements error. It never contains credentials.
func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("fpchecker: API error: HTTP %d (%s)", e.Status, e.Code)
	}
	return fmt.Sprintf("fpchecker: API error: HTTP %d", e.Status)
}

// Unwrap returns the transport error behind a network_error / timeout.
func (e *APIError) Unwrap() error { return e.Err }

// Sealed result error codes.
const (
	SealedBadFormat          = "bad_format"
	SealedUnknownKey         = "unknown_key"
	SealedDecryptFailed      = "decrypt_failed"
	SealedInvalidKey         = "invalid_key"
	SealedUnsupportedVersion = "unsupported_version"
)

// SealedResultError is returned by UnsealResult; Code is one of the Sealed* constants.
type SealedResultError struct{ Code string }

func (e *SealedResultError) Error() string { return "fpchecker: sealed result: " + e.Code }

// Webhook signature error codes.
const (
	WebhookExpired         = "expired"
	WebhookFuture          = "future"
	WebhookBadSignature    = "bad_signature"
	WebhookMalformedHeader = "malformed_header"
)

// WebhookSignatureError is returned by VerifyWebhookSignature; Code is one of the Webhook* constants.
type WebhookSignatureError struct{ Code string }

func (e *WebhookSignatureError) Error() string { return "fpchecker: webhook signature: " + e.Code }
