package fpchecker

import (
	"encoding/json"
	"errors"
)

// RuleAction is what the project's ruleset decided for an event. Type is
// allow | human_check | deny | none; it is an open string, so a value added
// by a newer server does not fail parsing (treat unknown as none).
type RuleAction struct {
	Type           string `json:"type"`
	RuleID         string `json:"ruleId,omitempty"`
	RuleName       string `json:"ruleName,omitempty"`
	RulesetVersion int    `json:"rulesetVersion"`
}

// WebhookEventData is the event inside a webhook body. Proxied and RuleAction
// are pointers: nil means the payload lacked them (queued before server
// 0.45.0, or RuleAction was JSON null because the ruleset is disabled).
type WebhookEventData struct {
	VisitorID  string      `json:"visitorId"`
	Proxied    *bool       `json:"proxied,omitempty"`
	RuleAction *RuleAction `json:"ruleAction,omitempty"`
	// Signals is the zero value when the payload lacks them (queued before server 0.43.0).
	Signals EventSignals `json:"signals"`
}

// EventSignals holds the signals this SDK types; every other signal is left in WebhookEvent.Raw.
type EventSignals struct {
	Vpn VpnSignal `json:"vpn"`
	// Mobile is nil for web events and when the payload has none.
	Mobile *MobileSignals `json:"mobile"`
}

// VpnSignal carries the methods that reached the VPN verdict. Methods is an open set
// (timezone_mismatch, ip_range, relay, os_vpn, ...): ignore a value you do not know.
type VpnSignal struct {
	Result  *bool    `json:"result"`
	Methods []string `json:"methods"`
}

// UnmarshalJSON tolerates a wrong type anywhere in the object.
func (v *VpnSignal) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		*v = VpnSignal{}
		return nil
	}
	out := VpnSignal{Result: triBool(m["result"])}
	var methods []any
	if json.Unmarshal(m["methods"], &methods) == nil {
		for _, x := range methods {
			if s, ok := x.(string); ok {
				out.Methods = append(out.Methods, s)
			}
		}
	}
	*v = out
	return nil
}

// MobileSignals are device-state signals of an android, ios or macos event. Each flag is
// true (detected), false (checked, nothing found) or nil (not checked: old SDK, probes switched
// off, unsupported platform). Not a guarantee either way. FactoryResetAt is reserved and
// currently always nil.
type MobileSignals struct {
	Emulator        *bool   `json:"emulator"`
	Attested        *bool   `json:"attested"`
	Integrity       string  `json:"integrity,omitempty"` // strong | basic | failed | "" when unknown
	Rooted          *bool   `json:"rooted"`
	Hooked          *bool   `json:"hooked"`
	Debugger        *bool   `json:"debugger"`
	DeveloperMode   *bool   `json:"developerMode"`
	Mitm            *bool   `json:"mitm"`
	Vpn             *bool   `json:"vpn"`
	LocationSpoofed *bool   `json:"locationSpoofed"`
	ClonedApp       *bool   `json:"clonedApp"`
	FactoryResetAt  *string `json:"factoryResetAt"`
}

func triBool(raw json.RawMessage) *bool {
	var b bool
	if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &b) != nil {
		return nil
	}
	return &b
}

// UnmarshalJSON reads every flag as true, false or nil; a wrong type is nil, never an error.
func (m *MobileSignals) UnmarshalJSON(b []byte) error {
	var f map[string]json.RawMessage
	if json.Unmarshal(b, &f) != nil {
		*m = MobileSignals{}
		return nil
	}
	out := MobileSignals{
		Emulator:        triBool(f["emulator"]),
		Attested:        triBool(f["attested"]),
		Rooted:          triBool(f["rooted"]),
		Hooked:          triBool(f["hooked"]),
		Debugger:        triBool(f["debugger"]),
		DeveloperMode:   triBool(f["developerMode"]),
		Mitm:            triBool(f["mitm"]),
		Vpn:             triBool(f["vpn"]),
		LocationSpoofed: triBool(f["locationSpoofed"]),
		ClonedApp:       triBool(f["clonedApp"]),
	}
	var s string
	if json.Unmarshal(f["integrity"], &s) == nil && (s == "strong" || s == "basic" || s == "failed") {
		out.Integrity = s
	}
	if r := f["factoryResetAt"]; string(r) != "null" && json.Unmarshal(r, &s) == nil {
		out.FactoryResetAt = &s
	}
	*m = out
	return nil
}

// WebhookEvent is a parsed webhook body. Raw keeps every field.
type WebhookEvent struct {
	ID   string           `json:"id"`
	Type string           `json:"type"`
	Data WebhookEventData `json:"data"`
	Raw  json.RawMessage  `json:"-"`
}

// ParseWebhookEvent parses a webhook body (verify its signature first).
func ParseWebhookEvent(rawBody []byte) (*WebhookEvent, error) {
	var e WebhookEvent
	if err := json.Unmarshal(rawBody, &e); err != nil {
		return nil, err
	}
	if e.Data.VisitorID == "" {
		return nil, errors.New("fpchecker: not a webhook event")
	}
	e.Raw = append(json.RawMessage(nil), rawBody...)
	return &e, nil
}

// EligibilityAnswer is the answer of CheckEligibility. Reason is an open
// string. RuleID is set only when a rule decided the answer or an allow rule
// applied.
type EligibilityAnswer struct {
	OK       bool   `json:"ok"`
	Eligible *bool  `json:"eligible,omitempty"`
	Action   string `json:"action,omitempty"`
	Reason   string `json:"reason,omitempty"`
	RuleID   string `json:"ruleId,omitempty"`
}

// ParseEligibilityAnswer decodes a CheckEligibility response.
func ParseEligibilityAnswer(raw []byte) (*EligibilityAnswer, error) {
	var a EligibilityAnswer
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	return &a, nil
}
