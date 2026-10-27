package fpchecker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// BotInfo is one entry of the Bot directory and how well the request matched it.
// Category and Identity are open strings: treat an unknown category as "other".
type BotInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Category string `json:"category"` // search_crawler | ai_crawler | ai_search | ai_assistant | ai_agent | seo | monitoring | social_preview | advertising | aggregator | scraping | other
	Identity string `json:"identity"` // verified | signed | unknown | spoofed
}

// BotSignal is the bot verdict, in a BotCheck answer and in event signals.
// Result is "not_detected", "good" (a directory bot that is verified or signed) or "bad";
// it is an open string, treat an unknown value as "bad". Result is "" when it was not checked.
// Info is nil when the request named no directory bot, and always nil for version 1 events
// (stored before server 0.48.0). Types is open: ignore a value you do not know.
type BotSignal struct {
	Result string   `json:"result"`
	Types  []string `json:"types"`
	Info   *BotInfo `json:"info"`
}

// UnmarshalJSON tolerates a wrong type anywhere in the object: a malformed field is zero/nil, never an error.
func (b *BotSignal) UnmarshalJSON(raw []byte) error {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		*b = BotSignal{}
		return nil
	}
	out := BotSignal{}
	if json.Unmarshal(m["result"], &out.Result) != nil {
		out.Result = ""
	}
	var types []any
	if json.Unmarshal(m["types"], &types) == nil {
		for _, x := range types {
			if s, ok := x.(string); ok {
				out.Types = append(out.Types, s)
			}
		}
	}
	var info map[string]any
	if json.Unmarshal(m["info"], &info) == nil && info != nil {
		str := func(k string) string { s, _ := info[k].(string); return s }
		if id := str("id"); id != "" {
			out.Info = &BotInfo{ID: id, Name: str("name"), Provider: str("provider"), Category: str("category"), Identity: str("identity")}
		}
	}
	*b = out
	return nil
}

// BotCheckRequest is the request your backend received. URL is as the visitor requested it
// (original host and scheme, not your origin behind a CDN). Build Headers with BotCheckHeaders.
type BotCheckRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	IP      string            `json:"ip"`
	Headers map[string]string `json:"headers"`
}

// BotCheckResult is the answer of BotCheck.
type BotCheckResult struct {
	Bot BotSignal `json:"bot"`
	IP  struct {
		Country    *string `json:"country"`
		ASN        *int64  `json:"asn"`
		ASName     *string `json:"asName"`
		Datacenter *bool   `json:"datacenter"`
		Tor        *bool   `json:"tor"`
		Relay      *bool   `json:"relay"`
		Blocklist  struct {
			Result  *bool    `json:"result"`
			Sources []string `json:"sources"`
		} `json:"blocklist"`
	} `json:"ip"`
	Vpn struct {
		Result  *bool    `json:"result"`
		Methods []string `json:"methods"`
	} `json:"vpn"`
	Proxy struct {
		Result *bool   `json:"result"`
		Type   *string `json:"type"`
	} `json:"proxy"`
}

// BotCheck classifies a request your backend received. It is not charged and writes no event.
// A 400 is an *APIError whose Code is invalid_request or invalid_ip and whose Body carries the
// offending "field".
func (c *Client) BotCheck(ctx context.Context, req BotCheckRequest) (*BotCheckResult, error) {
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	raw, err := c.do(ctx, "POST", "/v1/bot-check", nil, req, authSecret)
	if err != nil {
		return nil, err
	}
	var out BotCheckResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("fpchecker: decode bot-check answer: %w", err)
	}
	return &out, nil
}

// botCheckHeaders is the only set of request headers BotCheck needs. Never Cookie or Authorization.
var botCheckHeaders = map[string]bool{
	"user-agent": true, "accept": true, "accept-language": true, "accept-encoding": true,
	"sec-ch-ua": true, "sec-ch-ua-mobile": true, "sec-ch-ua-platform": true,
	"sec-fetch-site": true, "sec-fetch-mode": true, "sec-fetch-dest": true, "sec-fetch-user": true,
	"signature": true, "signature-input": true, "signature-agent": true,
	"upgrade-insecure-requests": true,
}

// BotCheckHeaders builds BotCheckRequest.Headers from a request's headers (r.Header). It keeps only
// the headers the check needs, with lower-cased names, and drops everything else, including Cookie
// and Authorization. h is expected to be canonical (as net/http delivers it). A header sent more than once is joined with ", ".
func BotCheckHeaders(h http.Header) map[string]string {
	out := make(map[string]string)
	for name, values := range h {
		key := strings.ToLower(name)
		if !botCheckHeaders[key] || len(values) == 0 {
			continue
		}
		out[key] = strings.Join(values, ", ")
	}
	return out
}
