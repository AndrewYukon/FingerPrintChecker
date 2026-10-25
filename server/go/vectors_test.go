package fpchecker

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
)

func loadJSON(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile("../../test-vectors/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func TestSealedVectors(t *testing.T) {
	var f struct {
		Keys  map[string]string `json:"keys"`
		Cases []struct {
			Name   string          `json:"name"`
			Keys   []string        `json:"keys"`
			Blob   string          `json:"blob"`
			Expect json.RawMessage `json:"expect"`
		} `json:"cases"`
	}
	loadJSON(t, "sealed-result-v1.json", &f)
	if len(f.Cases) != 17 {
		t.Fatalf("want 17 sealed cases, got %d", len(f.Cases))
	}
	ran := 0
	for _, c := range f.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			ran++
			keys := make([]string, 0, len(c.Keys))
			for _, k := range c.Keys {
				v, ok := f.Keys[k]
				if !ok {
					t.Fatalf("unknown key ref %q", k)
				}
				keys = append(keys, v)
			}
			res, err := UnsealResult(c.Blob, keys)
			var errExpect struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(c.Expect, &errExpect)
			if errExpect.Error != "" {
				var se *SealedResultError
				if !errors.As(err, &se) || se.Code != errExpect.Error {
					t.Fatalf("want error %s, got res=%v err=%v", errExpect.Error, res, err)
				}
				if res != nil {
					t.Fatal("result must be nil on error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var want map[string]any
			if err := json.Unmarshal(c.Expect, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(res.Raw, want) {
				t.Fatalf("payload mismatch:\n got %v\nwant %v", res.Raw, want)
			}
			if res.EventID != "ev_0123456789ABCDEFGHJK" || res.Timestamp != 1761400000000 || res.Tags["plan"] != "pro" || res.Version != 1 {
				t.Fatalf("typed fields wrong: %+v", res)
			}
		})
	}
	if ran != 17 {
		t.Fatalf("ran %d of 17", ran)
	}
}

func TestSealedKeyEdgeCases(t *testing.T) {
	var f struct {
		Keys  map[string]string             `json:"keys"`
		Cases []struct{ Name, Blob string } `json:"cases"`
	}
	loadJSON(t, "sealed-result-v1.json", &f)
	blob := f.Cases[0].Blob
	for name, keys := range map[string][]string{
		"empty key":      {""},
		"urlsafe key":    {"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"},
		"padded newline": {f.Keys["a"] + "\n"},
	} {
		_, err := UnsealResult(blob, keys)
		var se *SealedResultError
		if !errors.As(err, &se) || se.Code != "invalid_key" {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := UnsealResult(blob, nil); err == nil {
		t.Error("no keys must fail")
	}
}

func TestWebhookVectors(t *testing.T) {
	var f struct {
		Secret string `json:"secret"`
		Cases  []struct {
			Name   string          `json:"name"`
			Body   string          `json:"body"`
			Header string          `json:"header"`
			Now    int64           `json:"now"`
			Expect json.RawMessage `json:"expect"`
		} `json:"cases"`
	}
	loadJSON(t, "webhook-signature.json", &f)
	if len(f.Cases) != 15 {
		t.Fatalf("want 15 webhook cases, got %d", len(f.Cases))
	}
	ran := 0
	for _, c := range f.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			ran++
			err := VerifyWebhookSignature([]byte(c.Body), c.Header, f.Secret, 300*time.Second, time.Unix(c.Now, 0))
			var e struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(c.Expect, &e) == nil && e.Error != "" {
				var we *WebhookSignatureError
				if !errors.As(err, &we) || we.Code != e.Error {
					t.Fatalf("want %s, got %v", e.Error, err)
				}
				return
			}
			if string(c.Expect) != "true" || err != nil {
				t.Fatalf("want ok, got %v", err)
			}
		})
	}
	if ran != 15 {
		t.Fatalf("ran %d of 15", ran)
	}
}

func TestWebhookNegativeToleranceAndZeroNow(t *testing.T) {
	err := VerifyWebhookSignature([]byte("x"), "t=1,v1=00", "s", -time.Second, time.Unix(1, 0))
	if err == nil {
		t.Fatal("negative tolerance must error")
	}
	var we *WebhookSignatureError
	if errors.As(err, &we) {
		t.Fatal("negative tolerance is a usage error, not a signature error")
	}
	// zero tolerance, exact time still valid
	var f struct {
		Secret string                          `json:"secret"`
		Cases  []struct{ Body, Header string } `json:"cases"`
	}
	loadJSON(t, "webhook-signature.json", &f)
	if err := VerifyWebhookSignature([]byte(f.Cases[0].Body), f.Cases[0].Header, f.Secret, 0, time.Unix(1761400000, 0)); err != nil {
		t.Fatal(err)
	}
}
