package fpchecker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	tPattern       = regexp.MustCompile(`^[0-9]{1,12}$`)
	hex64          = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	errEmptySecret = errors.New("fpchecker: webhook secret must not be empty")
	errNegTol      = errors.New("fpchecker: webhook tolerance must be >= 0")
	wsChars        = " \t\r\n"
)

// DefaultWebhookTolerance is the recommended replay window.
const DefaultWebhookTolerance = 300 * time.Second

func parseSignatureHeader(header string) (tRaw string, t int64, v1 []string, ok bool) {
	if strings.ContainsAny(header, wsChars) {
		return
	}
	seenT := false
	for _, part := range strings.Split(header, ",") {
		key, value, found := strings.Cut(part, "=")
		if part == "" || !found {
			return
		}
		switch key {
		case "t":
			if seenT {
				return
			}
			seenT, tRaw = true, value
		case "v1":
			v1 = append(v1, value)
		}
	}
	if !seenT || !tPattern.MatchString(tRaw) || len(v1) == 0 {
		return
	}
	n, err := strconv.ParseInt(tRaw, 10, 64)
	if err != nil {
		return
	}
	return tRaw, n, v1, true
}

// VerifyWebhookSignature returns nil if header (the FPC-Signature value) is a
// valid, fresh signature of rawBody, which must be the exact bytes received.
// Failures are *WebhookSignatureError; a negative tolerance is a plain error.
// Check order: header, signature, then the time window (so forged requests
// learn nothing about the clock). A zero now means time.Now().
func VerifyWebhookSignature(rawBody []byte, header, secret string, tolerance time.Duration, now time.Time) error {
	if secret == "" {
		return errEmptySecret
	}
	if tolerance < 0 {
		return errNegTol
	}
	if now.IsZero() {
		now = time.Now()
	}
	tRaw, t, v1, ok := parseSignatureHeader(header)
	if !ok {
		return &WebhookSignatureError{WebhookMalformedHeader}
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tRaw + "."))
	mac.Write(rawBody)
	expected := mac.Sum(nil)

	match := false
	for _, c := range v1 {
		if !hex64.MatchString(c) {
			continue
		}
		got, err := hex.DecodeString(c)
		if err == nil && hmac.Equal(got, expected) {
			match = true
		}
	}
	if !match {
		return &WebhookSignatureError{WebhookBadSignature}
	}

	stamp := time.Unix(t, 0)
	if now.Sub(stamp) > tolerance {
		return &WebhookSignatureError{WebhookExpired}
	}
	if stamp.Sub(now) > tolerance {
		return &WebhookSignatureError{WebhookFuture}
	}
	return nil
}
