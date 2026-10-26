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
