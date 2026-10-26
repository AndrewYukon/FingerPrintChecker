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
