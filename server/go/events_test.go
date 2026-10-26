package fpchecker

import (
	"testing"
	"time"
)

func evBody(extra string) []byte {
	return []byte(`{"id":"evt_1","type":"identify","data":{"visitorId":"v_1"` + extra + `}}`)
}

func TestOkRuleActionVector(t *testing.T) {
	var f struct {
		Secret string `json:"secret"`
		Cases  []struct {
			Name, Body, Header string
			Now                int64
		} `json:"cases"`
	}
	loadJSON(t, "webhook-signature.json", &f)
	found := false
	for _, c := range f.Cases {
		if c.Name != "ok_rule_action" {
			continue
		}
		found = true
		if err := VerifyWebhookSignature([]byte(c.Body), c.Header, f.Secret, 300*time.Second, time.Unix(c.Now, 0)); err != nil {
			t.Fatal(err)
		}
		e, err := ParseWebhookEvent([]byte(c.Body))
		if err != nil {
			t.Fatal(err)
		}
		ra := e.Data.RuleAction
		if e.Data.Proxied == nil || !*e.Data.Proxied || ra == nil ||
			*ra != (RuleAction{Type: "deny", RuleID: "r_0a1b2c3d", RuleName: "Block hosting", RulesetVersion: 3}) {
			t.Fatalf("bad parse: %+v %+v", e.Data, ra)
		}
	}
	if !found {
		t.Fatal("vector ok_rule_action missing")
	}
}

func TestRuleActionTypesAndOptionalFields(t *testing.T) {
	for _, ty := range []string{"allow", "human_check", "deny", "none", "captcha"} {
		e, err := ParseWebhookEvent(evBody(`,"proxied":false,"ruleAction":{"type":"` + ty + `","rulesetVersion":1}`))
		if err != nil {
			t.Fatal(err)
		}
		if e.Data.RuleAction == nil || e.Data.RuleAction.Type != ty || e.Data.Proxied == nil || *e.Data.Proxied {
			t.Fatalf("%s: %+v", ty, e.Data)
		}
	}
	for _, extra := range []string{``, `,"ruleAction":null`} {
		e, err := ParseWebhookEvent(evBody(extra))
		if err != nil || e.Data.RuleAction != nil || e.Data.Proxied != nil {
			t.Fatalf("%q: %+v %v", extra, e, err)
		}
	}
	if _, err := ParseWebhookEvent([]byte(`{"a":1}`)); err == nil {
		t.Fatal("non-event must error")
	}
}

func TestEligibilityRuleID(t *testing.T) {
	a, err := ParseEligibilityAnswer([]byte(`{"ok":true,"eligible":false,"action":"deny","reason":"rule_deny","ruleId":"r_1"}`))
	if err != nil || a.RuleID != "r_1" || a.Reason != "rule_deny" || a.Eligible == nil || *a.Eligible {
		t.Fatalf("%+v %v", a, err)
	}
	b, _ := ParseEligibilityAnswer([]byte(`{"ok":true,"eligible":true,"reason":"brand_new"}`))
	if b.RuleID != "" {
		t.Fatal("ruleId must be empty")
	}
}

func TestOkMobileSignalsVector(t *testing.T) {
	var f struct {
		Secret string `json:"secret"`
		Cases  []struct {
			Name, Body, Header string
			Now                int64
		} `json:"cases"`
	}
	loadJSON(t, "webhook-signature.json", &f)
	found := false
	for _, c := range f.Cases {
		if c.Name != "ok_mobile_signals" {
			continue
		}
		found = true
		if err := VerifyWebhookSignature([]byte(c.Body), c.Header, f.Secret, 300*time.Second, time.Unix(c.Now, 0)); err != nil {
			t.Fatal(err)
		}
		e, err := ParseWebhookEvent([]byte(c.Body))
		if err != nil {
			t.Fatal(err)
		}
		m := e.Data.Signals.Mobile
		if m == nil || !isTrue(m.Rooted) || !isFalse(m.Hooked) || !isTrue(m.DeveloperMode) || !isTrue(m.Vpn) ||
			m.LocationSpoofed != nil || m.FactoryResetAt != nil {
			t.Fatalf("bad mobile: %+v", m)
		}
		if !hasString(e.Data.Signals.Vpn.Methods, "os_vpn") {
			t.Fatal("os_vpn missing")
		}
	}
	if !found {
		t.Fatal("vector ok_mobile_signals missing")
	}
}

func isTrue(b *bool) bool  { return b != nil && *b }
func isFalse(b *bool) bool { return b != nil && !*b }
func hasString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestOldPayloadMobileFieldsAreNil(t *testing.T) {
	e, err := ParseWebhookEvent(evBody(`,"signals":{"mobile":{"emulator":false,"attested":true,"integrity":"strong"}}`))
	if err != nil {
		t.Fatal(err)
	}
	m := e.Data.Signals.Mobile
	if m == nil || m.Rooted != nil || m.ClonedApp != nil || m.FactoryResetAt != nil || !isFalse(m.Emulator) {
		t.Fatalf("%+v", m)
	}
	for _, extra := range []string{``, `,"signals":{"mobile":null}`} {
		e, err := ParseWebhookEvent(evBody(extra))
		if err != nil || e.Data.Signals.Mobile != nil || len(e.Data.Signals.Vpn.Methods) != 0 {
			t.Fatalf("%q: %+v %v", extra, e, err)
		}
	}
}

func TestUnknownVpnMethodAndWrongTypesDoNotFail(t *testing.T) {
	e, err := ParseWebhookEvent(evBody(`,"signals":{"vpn":{"result":true,"methods":["os_vpn","future"]},"mobile":{"rooted":"yes","factoryResetAt":"2026-10-01"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.Data.Signals.Mobile.Rooted != nil || e.Data.Signals.Mobile.FactoryResetAt == nil || len(e.Data.Signals.Vpn.Methods) != 2 {
		t.Fatalf("%+v", e.Data.Signals)
	}
}
