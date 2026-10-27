package fpchecker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

const botVerdict = `{"bot":{"result":"good","types":[],"info":{"id":"googlebot","name":"Googlebot","provider":"Google","category":"search_crawler","identity":"verified"}},
"ip":{"country":"US","asn":15169,"asName":"Google LLC","datacenter":true,"tor":false,"relay":false,"blocklist":{"result":false,"sources":[]}},
"vpn":{"result":false,"methods":[]},"proxy":{"result":false,"type":null}}`

func botReq() BotCheckRequest {
	return BotCheckRequest{Method: "GET", URL: "https://shop.example/pricing", IP: "66.249.66.1", Headers: map[string]string{"user-agent": "Googlebot/2.1"}}
}

func TestBotCheckSendsBodyAndParsesVerdict(t *testing.T) {
	var gotBody map[string]any
	var gotPath, gotMethod, gotKey string
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotKey = r.URL.Path, r.Method, r.Header.Get("X-Secret-Key")
		_, _ = w.Write([]byte(botVerdict))
	}}
	c, _ := newTestClient(t, rec)
	res, err := c.BotCheck(context.Background(), botReq())
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(rec.reqs[0].Body), &gotBody)
	if gotPath != "/v1/bot-check" || gotMethod != "POST" || gotKey != testSecret {
		t.Fatalf("%s %s key=%q", gotMethod, gotPath, gotKey)
	}
	want := map[string]any{"method": "GET", "url": "https://shop.example/pricing", "ip": "66.249.66.1", "headers": map[string]any{"user-agent": "Googlebot/2.1"}}
	if !reflect.DeepEqual(gotBody, want) {
		t.Fatalf("body %v", gotBody)
	}
	if res.Bot.Result != "good" || res.Bot.Info == nil || res.Bot.Info.Identity != "verified" || res.Bot.Info.ID != "googlebot" {
		t.Fatalf("bot %+v", res.Bot)
	}
	if res.IP.ASN == nil || *res.IP.ASN != 15169 || res.Proxy.Type != nil || res.Vpn.Result == nil || *res.Vpn.Result {
		t.Fatalf("ip/vpn/proxy %+v", res)
	}
}

func TestBotCheckNilHeadersSentAsObject(t *testing.T) {
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(botVerdict))
	}}
	c, _ := newTestClient(t, rec)
	if _, err := c.BotCheck(context.Background(), BotCheckRequest{Method: "GET", URL: "https://x.test/", IP: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if gotBody := rec.reqs[0].Body; gotBody != `{"method":"GET","url":"https://x.test/","ip":"1.1.1.1","headers":{}}` {
		t.Fatal(gotBody)
	}
}

func TestBotCheckErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		code   string
	}{
		{400, `{"ok":false,"error":"invalid_request","field":"url"}`, "invalid_request"},
		{400, `{"ok":false,"error":"invalid_ip","field":"ip"}`, "invalid_ip"},
		{401, `{"ok":false,"error":"unauthorized"}`, "unauthorized"},
		{429, `{"ok":false,"error":"rate_limited"}`, "rate_limited"},
	} {
		rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}}
		c, _ := newTestClient(t, rec)
		res, err := c.BotCheck(context.Background(), botReq())
		var apiErr *APIError
		if res != nil || !errors.As(err, &apiErr) || apiErr.Status != tc.status || apiErr.Code != tc.code {
			t.Fatalf("%d: res=%v err=%v", tc.status, res, err)
		}
		if tc.status == 400 {
			var b struct{ Field string }
			_ = json.Unmarshal(apiErr.Body, &b)
			if b.Field == "" {
				t.Fatalf("field missing: %s", apiErr.Body)
			}
		}
		if rec.count() != 1 {
			t.Fatalf("%d: POST retried (%d requests)", tc.status, rec.count())
		}
	}
}

func TestBotCheckHeadersKeepsAllowedDropsSecrets(t *testing.T) {
	h := http.Header{}
	allowed := map[string]string{
		"User-Agent": "UA", "Accept": "text/html", "Accept-Language": "en", "Accept-Encoding": "gzip",
		"Sec-Ch-Ua": `"x"`, "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": `"macOS"`,
		"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1",
		"Signature": "sig1=:a:", "Signature-Input": "sig1=()", "Signature-Agent": `"https://chatgpt.com"`,
		"Upgrade-Insecure-Requests": "1",
	}
	for k, v := range allowed {
		h.Set(k, v)
	}
	h.Set("Cookie", "sid=1")
	h.Set("Authorization", "Bearer x")
	h.Set("X-Forwarded-For", "1.1.1.1")
	h.Add("Accept", "image/png")
	got := BotCheckHeaders(h)
	if len(got) != len(allowed) {
		t.Fatalf("got %v", got)
	}
	if _, ok := got["cookie"]; ok {
		t.Fatal("cookie forwarded")
	}
	if _, ok := got["authorization"]; ok {
		t.Fatal("authorization forwarded")
	}
	if got["accept"] != "text/html, image/png" || got["user-agent"] != "UA" || got["sec-ch-ua"] != `"x"` {
		t.Fatalf("values %v", got)
	}
}

func TestEventSignalsV1AndV2(t *testing.T) {
	v1, err := ParseWebhookEvent(evBody(`,"signals":{"version":1,"bot":{"result":"bad","types":["webdriver"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := v1.Data.Signals
	if s.Version != 1 || s.Bot.Result != "bad" || s.Bot.Info != nil || len(s.Bot.Types) != 1 {
		t.Fatalf("v1 %+v", s)
	}
	v2, err := ParseWebhookEvent(evBody(`,"signals":{"version":2,"bot":{"result":"good","types":[],"info":{"id":"googlebot","name":"Googlebot","provider":"Google","category":"search_crawler","identity":"signed"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	s = v2.Data.Signals
	if s.Version != 2 || s.Bot.Result != "good" || s.Bot.Info == nil || s.Bot.Info.Identity != "signed" || s.Bot.Info.Category != "search_crawler" {
		t.Fatalf("v2 %+v", s)
	}
	n, err := ParseWebhookEvent(evBody(`,"signals":{"version":2,"bot":{"result":"not_detected","types":[],"info":null}}`))
	if err != nil || n.Data.Signals.Bot.Info != nil {
		t.Fatalf("null info: %+v %v", n, err)
	}
}

func TestBotSearchFiltersForwarded(t *testing.T) {
	var gotQuery string
	rec := &recorder{serve: func(w http.ResponseWriter, r *http.Request) { gotQuery = r.URL.RawQuery; _, _ = w.Write([]byte(`{}`)) }}
	c, _ := newTestClient(t, rec)
	_, err := c.SearchEvents(context.Background(), Query{"bot_result": "good", "bot_category": "ai_crawler", "bot_identity": "signed", "bot_id": "googlebot"})
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "bot_category=ai_crawler&bot_id=googlebot&bot_identity=signed&bot_result=good" {
		t.Fatal(gotQuery)
	}
}

func TestBotCheckHeadersFollowSignatureInput(t *testing.T) {
	h := http.Header{}
	h.Set("Signature-Input", `sig1=("@authority" "content-type" "X-Custom" "cookie" "signature-agent");created=1;keyid="k";tag="web-bot-auth"`)
	h.Set("Signature-Agent", `"https://chatgpt.com"`)
	h.Set("Content-Type", "text/plain")
	h.Set("X-Custom", "v")
	h.Set("X-Other", "no")
	h.Set("Cookie", "sid=1")
	h.Set("Authorization", "x")
	got := BotCheckHeaders(h)
	if got["content-type"] != "text/plain" || got["x-custom"] != "v" {
		t.Fatalf("covered components missing: %v", got)
	}
	for _, k := range []string{"x-other", "cookie", "authorization"} {
		if _, ok := got[k]; ok {
			t.Fatalf("%s forwarded", k)
		}
	}
	plain := http.Header{}
	plain.Set("Content-Type", "x")
	plain.Set("User-Agent", "u")
	if g := BotCheckHeaders(plain); len(g) != 1 || g["user-agent"] != "u" {
		t.Fatalf("%v", g)
	}
}
