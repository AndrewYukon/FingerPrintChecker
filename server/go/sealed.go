package fpchecker

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"unicode/utf8"
)

var (
	b64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	sealMagic  = []byte("fps1")
)

const sealMinLen = 4 + 4 + 12 + 16

// SealedResult is the decrypted payload of the sealedResult returned by /v2/identify.
// Raw holds every field of the payload (numbers as float64), so fields added
// by newer servers are not lost.
type SealedResult struct {
	Version     int
	EventID     string
	VisitorID   string
	ProjectID   string
	LinkedID    string
	Tags        map[string]string
	Timestamp   int64
	Platform    string
	ProofStatus string
	Raw         map[string]any
}

// strictB64 accepts canonical standard base64 only: regex, length%4,
// decode, re-encode equality (StdEncoding.Strict alone is not enough).
func strictB64(s string) ([]byte, bool) {
	if len(s)%4 != 0 || !b64Pattern.MatchString(s) {
		return nil, false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s {
		return nil, false
	}
	return raw, true
}

// UnsealResult decrypts a sealed result. keys are base64 32-byte project
// keys (pass active and previous during rotation). Errors are *SealedResultError.
func UnsealResult(blob string, keys []string) (*SealedResult, error) {
	keyBytes := make([][]byte, 0, len(keys))
	for _, k := range keys {
		b, ok := strictB64(k)
		if !ok || len(b) != 32 {
			return nil, &SealedResultError{SealedInvalidKey}
		}
		keyBytes = append(keyBytes, b)
	}

	raw, ok := strictB64(blob)
	if !ok || len(raw) < sealMinLen || !bytes.Equal(raw[:4], sealMagic) {
		return nil, &SealedResultError{SealedBadFormat}
	}
	aad, keyID := raw[:8], raw[4:8]
	nonce, ct := raw[8:20], raw[20:]

	var candidates [][]byte
	for _, k := range keyBytes {
		sum := sha256.Sum256(k)
		if bytes.Equal(sum[:4], keyID) {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		return nil, &SealedResultError{SealedUnknownKey}
	}

	var plain []byte
	for _, k := range candidates {
		block, err := aes.NewCipher(k)
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		if p, err := gcm.Open(nil, nonce, ct, aad); err == nil {
			plain = p
			break
		}
	}
	if plain == nil {
		return nil, &SealedResultError{SealedDecryptFailed}
	}

	// encoding/json replaces invalid UTF-8 silently; reject it explicitly.
	// It also rejects NaN/Infinity and trailing garbage.
	var parsed map[string]any
	if !utf8.Valid(plain) || json.Unmarshal(plain, &parsed) != nil || parsed == nil {
		return nil, &SealedResultError{SealedDecryptFailed}
	}
	if v, ok := parsed["version"].(float64); !ok || v != 1 {
		return nil, &SealedResultError{SealedUnsupportedVersion}
	}
	return newSealedResult(parsed), nil
}

func newSealedResult(m map[string]any) *SealedResult {
	str := func(k string) string { s, _ := m[k].(string); return s }
	r := &SealedResult{
		Version:     1,
		EventID:     str("eventId"),
		VisitorID:   str("visitorId"),
		ProjectID:   str("projectId"),
		LinkedID:    str("linkedId"),
		Platform:    str("platform"),
		ProofStatus: str("proofStatus"),
		Raw:         m,
	}
	if ts, ok := m["timestamp"].(float64); ok {
		r.Timestamp = int64(ts)
	}
	if tags, ok := m["tags"].(map[string]any); ok {
		r.Tags = make(map[string]string, len(tags))
		for k, v := range tags {
			if s, ok := v.(string); ok {
				r.Tags[k] = s
			}
		}
	}
	return r
}
