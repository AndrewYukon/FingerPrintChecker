// fpchecker CLI identify (Go 1.21+, stdlib only). Env: FPC_PK, FPC_INTENT (v2) or FPC_SEAL (v1), FPC_TENANT, FPC_BASE, FPC_POW (default 16).
// v2 (recommended): go run identify.go --intent <intentToken>   (your backend mints it with POST /v2/intents). v1: needs FPC_SEAL.
// Optional event fields: --linked-id <id> (1-256 chars, no control chars) and --tags '<json object>' (<= 4096 bytes, nested <= 3 levels, an array counts as a level).
// They sit beside the signed fields; the answer's eventId identifies the event. Bad values exit 2 before any request.
// Self-test: go run identify.go --self-test   (checks ../../test-vectors/protocol-v2.json and the event-field rules)
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--self-test" {
		os.Exit(selfTest())
	}
	intent := os.Getenv("FPC_INTENT")
	if f := missingValue(args); f != "" {
		fmt.Fprintln(os.Stderr, f+" needs a value")
		os.Exit(2)
	}
	var linkedID, tagsJSON *string
	for i, a := range args {
		if i+1 >= len(args) {
			continue
		}
		switch a {
		case "--intent":
			intent = args[i+1]
		case "--linked-id":
			linkedID = &args[i+1]
		case "--tags":
			tagsJSON = &args[i+1]
		}
	}
	fields, err := eventFields(linkedID, tagsJSON)
	if err != nil { // before any request
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	base, pk, nbits := env("FPC_BASE", "https://api.fpchecker.com"), os.Getenv("FPC_PK"), env("FPC_POW", "16")
	if pk == "" || (intent == "" && os.Getenv("FPC_SEAL") == "") {
		fmt.Fprintln(os.Stderr, "set FPC_PK, and give --intent <intentToken> (or FPC_INTENT) for v2 or FPC_SEAL for v1")
		os.Exit(2)
	}
	home, _ := os.UserHomeDir()
	idFile := filepath.Join(home, ".config", env("FPC_TENANT", "fpchecker"), "device-id")
	id, err := os.ReadFile(idFile)
	if err != nil {
		b := make([]byte, 16)
		rand.Read(b)
		b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
		id = []byte(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]))
		os.MkdirAll(filepath.Dir(idFile), 0o700)
		os.WriteFile(idFile, id, 0o600)
	}
	comps := []map[string]string{{"key": "cli.randomId", "value": strings.TrimSpace(string(id))}, {"key": "cli.osVersion", "value": runtime.GOOS + "-" + runtime.GOARCH}}
	if link, err := filepath.EvalSymlinks("/etc/localtime"); err == nil {
		if i := strings.Index(link, "zoneinfo/"); i >= 0 {
			comps = append(comps, map[string]string{"key": "cli.timezone", "value": link[i+9:]})
		}
	}
	if out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil { // macOS hardware UUID
		if m := regexp.MustCompile(`"IOPlatformUUID" = "([0-9A-F-]{36})"`).FindSubmatch(out); m != nil {
			comps = append(comps, map[string]string{"key": "cli.platformUuid", "value": string(m[1])})
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	call := func(method, path string, body any) map[string]any {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(b))
		req.Header.Set("content-type", "application/json")
		req.Header.Set("x-publishable-key", pk)
		res, err := client.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer res.Body.Close()
		var out map[string]any
		json.NewDecoder(res.Body).Decode(&out)
		return out
	}
	need, _ := strconv.Atoi(nbits)
	if intent != "" { // v2: nothing is sealed or bound; the answer carries an opaque attestation
		ch := call("GET", "/v2/challenge?intent="+url.QueryEscape(intent)+"&difficulty="+nbits, nil)
		challenge, _ := ch["challenge"].(string)
		if ch["ok"] != true || challenge == "" {
			fmt.Fprintln(os.Stderr, ch)
			os.Exit(1)
		}
		const agent = "cli-go-0.4.0"
		if _, err := identifyCanonical("cli", agent, challenge, comps); err != nil { // refuse locally what the server refuses
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		answer := call("POST", "/v2/identify", withFields(map[string]any{"protocolVersion": 2, "platform": "cli", "intentToken": intent, "challenge": challenge, "agentVersion": agent, "components": comps, "pow": solve(challenge, need)}, fields))
		out, _ := json.MarshalIndent(answer, "", "  ")
		fmt.Println(string(out))                                                         // hand `attestation` to your backend for /v1/eligibility
		if att, _ := answer["attestation"].(string); answer["ok"] != true || att == "" { // success without an attestation = failure
			os.Exit(1)
		}
		return
	}
	nonce := call("GET", "/v1/challenge?difficulty="+nbits, nil)["nonce"].(string)
	parts := []string{}
	for _, c := range comps {
		parts = append(parts, c["key"]+"="+c["value"])
	}
	sort.Strings(parts) // sort the key=value strings
	mac := hmac.New(sha256.New, []byte(os.Getenv("FPC_SEAL")))
	mac.Write([]byte(nonce + "|" + strings.Join(parts, "|")))
	out, _ := json.MarshalIndent(call("POST", "/v1/identify", withFields(map[string]any{"platform": "cli", "nonce": nonce, "sig": hex.EncodeToString(mac.Sum(nil)), "components": comps, "agentVersion": "cli-go-1", "pow": solve(nonce, need)}, fields)), "", "  ")
	fmt.Println(string(out))
}

// missingValue returns the first value-taking flag that has no value after it, or "".
func missingValue(args []string) string {
	if n := len(args); n > 0 {
		for _, f := range []string{"--intent", "--linked-id", "--tags"} {
			if args[n-1] == f {
				return f
			}
		}
	}
	return ""
}

// withFields merges the event fields (linkedId, tags) into a request body, beside the signed fields.
func withFields(body map[string]any, fields map[string]any) map[string]any {
	for k, v := range fields {
		body[k] = v
	}
	return body
}

// --- optional event fields (linkedId, tags): the server's rules, checked before any request; never part of the signed bytes ---

var controlRe = regexp.MustCompile("[\\x00-\\x1f\\x7f]")

func tagsWithinDepth(v any, depth int) bool {
	switch x := v.(type) {
	case []any:
		if depth >= 3 {
			return false
		}
		for _, e := range x {
			if !tagsWithinDepth(e, depth+1) {
				return false
			}
		}
	case map[string]any:
		if depth > 3 {
			return false
		}
		for _, e := range x {
			if !tagsWithinDepth(e, depth+1) {
				return false
			}
		}
	}
	return true
}

// eventFields returns the body fragment ({} when neither is given); nil means "not set", as on the server.
func eventFields(linkedID, tagsJSON *string) (map[string]any, error) {
	out := map[string]any{}
	if linkedID != nil {
		if n := len(utf16.Encode([]rune(*linkedID))); n < 1 || n > 256 || controlRe.MatchString(*linkedID) {
			return nil, fmt.Errorf("invalid linkedId: 1-256 characters, no control characters")
		}
		out["linkedId"] = *linkedID
	}
	if tagsJSON != nil {
		var tags any
		if err := json.Unmarshal([]byte(*tagsJSON), &tags); err != nil {
			return nil, fmt.Errorf("invalid tags: not valid JSON")
		}
		if tags != nil { // JSON null means "not set"
			obj, ok := tags.(map[string]any)
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)                                                             // JSON.stringify (the server's measure) leaves < > & alone
			if !ok || !tagsWithinDepth(obj, 1) || enc.Encode(obj) != nil || buf.Len()-1 > 4096 { // Encode adds a newline
				return nil, fmt.Errorf("invalid tags: a JSON object of at most 4096 bytes, nested at most 3 levels (an array counts as a level)")
			}
			out["tags"] = obj
		}
	}
	return out, nil
}

func solve(challenge string, need int) string {
	for pow := 0; ; pow++ {
		d := sha256.Sum256([]byte(challenge + ":" + strconv.Itoa(pow)))
		z := 0
		for _, x := range d {
			z += bits.LeadingZeros8(x)
			if x != 0 {
				break
			}
		}
		if z >= need {
			return strconv.Itoa(pow)
		}
	}
}

// --- protocol v2 canonical bytes: RFC 8785 (JCS) of a fixed object, written by hand (encoding/json escapes '<', '&', U+2028) ---

var keyRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// jcsString refuses invalid UTF-8: a Go string cannot hold a lone surrogate, but its UTF-8 form (ED A0..BF xx) is invalid.
func jcsString(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("string is not well-formed UTF-16")
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

// identifyCanonical returns the canonical string; components may carry "hash" (web only, used by the vectors).
func identifyCanonical(platform, agentVersion, challenge string, components []map[string]string) (string, error) {
	if !utf8.ValidString(agentVersion) || len(utf16.Encode([]rune(agentVersion))) > 64 {
		return "", fmt.Errorf("bad agentVersion")
	}
	seen := map[string]bool{}
	for _, c := range components {
		if !keyRe.MatchString(c["key"]) {
			return "", fmt.Errorf("bad component key: %q", c["key"])
		}
		if seen[c["key"]] {
			return "", fmt.Errorf("duplicate component key: %s", c["key"])
		}
		seen[c["key"]] = true
	}
	sorted := append([]map[string]string{}, components...)
	sort.Slice(sorted, func(i, j int) bool { return utf16Less(sorted[i]["key"], sorted[j]["key"]) })
	items := []string{}
	for _, c := range sorted {
		k, e1 := jcsString(c["key"])
		v, e2 := jcsString(c["value"])
		if e1 != nil || e2 != nil {
			return "", fmt.Errorf("string is not well-formed UTF-16")
		}
		hash := ""
		if h, ok := c["hash"]; ok {
			hs, err := jcsString(h)
			if err != nil {
				return "", err
			}
			hash = `"hash":` + hs + ","
		}
		items = append(items, "{"+hash+`"key":`+k+`,"value":`+v+"}")
	}
	parts := map[string]string{}
	for name, val := range map[string]string{"agentVersion": agentVersion, "challenge": challenge, "platform": platform} {
		s, err := jcsString(val)
		if err != nil {
			return "", err
		}
		parts[name] = s
	}
	return `{"agentVersion":` + parts["agentVersion"] + `,"challenge":` + parts["challenge"] + `,"components":[` + strings.Join(items, ",") +
		`],"domain":"fpchecker.identify.v2","platform":` + parts["platform"] + `,"protocolVersion":2}`, nil
}

type vectorInput struct {
	Platform, AgentVersion, Challenge string
	Components                        []map[string]string
}

// selfTest checks every accept and reject case in test-vectors/protocol-v2.json; returns the exit code.
func selfTest() int {
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "test-vectors", "protocol-v2.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// encoding/json turns a lone surrogate escape into U+FFFD, so swap each one for U+FFFF first and
	// turn that back into the (invalid) UTF-8 bytes of a surrogate after decoding.
	lone := regexp.MustCompile(`\\u[dD][89abAB][0-9a-fA-F]{2}(\\u[dD][c-fC-F][0-9a-fA-F]{2})?|\\u[dD][c-fC-F][0-9a-fA-F]{2}`)
	raw = lone.ReplaceAllFunc(raw, func(m []byte) []byte {
		if len(m) == 12 {
			return m // a valid pair
		}
		return []byte(`￿`)
	})
	var v struct {
		Accept []struct {
			Name                                               string
			Input                                              vectorInput
			Canonical, RequestBindingHex, ClientDataHashBase64 string
		}
		Reject []struct {
			Name  string
			Input vectorInput
		}
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fix := func(in vectorInput) vectorInput {
		const bad = "\xed\xa0\x80"
		in.Challenge = strings.ReplaceAll(in.Challenge, "￿", bad)
		in.AgentVersion = strings.ReplaceAll(in.AgentVersion, "￿", bad)
		cs := []map[string]string{}
		for _, c := range in.Components {
			n := map[string]string{}
			for k, x := range c {
				n[k] = strings.ReplaceAll(x, "￿", bad)
			}
			cs = append(cs, n)
		}
		in.Components = cs
		return in
	}
	fail := 0
	check := func(ok bool, msg string) {
		if !ok {
			fail++
			fmt.Fprintln(os.Stderr, "FAIL "+msg)
		}
	}
	for _, a := range v.Accept {
		in := fix(a.Input)
		canonical, err := identifyCanonical(in.Platform, in.AgentVersion, in.Challenge, in.Components)
		if err != nil {
			check(false, a.Name+": "+err.Error())
			continue
		}
		d := sha256.Sum256([]byte(canonical))
		check(canonical == a.Canonical, a.Name+": canonical")
		check(hex.EncodeToString(d[:]) == a.RequestBindingHex, a.Name+": requestBindingHex")
		check(base64.StdEncoding.EncodeToString(d[:]) == a.ClientDataHashBase64, a.Name+": clientDataHashBase64")
	}
	for _, r := range v.Reject {
		in := fix(r.Input)
		_, err := identifyCanonical(in.Platform, in.AgentVersion, in.Challenge, in.Components)
		check(err != nil, r.Name+": must be refused")
	}
	str := func(s string) *string { return &s }
	f, err := eventFields(nil, nil)
	check(err == nil && len(f) == 0, "event fields: absent sends nothing")
	f, err = eventFields(nil, str("null"))
	check(err == nil && len(f) == 0, "event fields: null tags is not set")
	f, err = eventFields(str("o_1"), str(`{"a":{"b":{"c":1}},"l":[1]}`))
	out, _ := json.Marshal(f)
	check(err == nil && string(out) == `{"linkedId":"o_1","tags":{"a":{"b":{"c":1}},"l":[1]}}`, "event fields: valid")
	_, err = eventFields(str(strings.Repeat("a", 256)), nil)
	check(err == nil, "event fields: 256 chars")
	for _, bad := range []string{"", strings.Repeat("a", 257), "a\nb", "a\x7fb"} {
		_, err := eventFields(&bad, nil)
		check(err != nil, fmt.Sprintf("event fields: linkedId %q refused", bad))
	}
	big, _ := json.Marshal(map[string]string{"k": strings.Repeat("a", 4096)})
	euro, _ := json.Marshal(map[string]string{"k": strings.Repeat("\u20ac", 1366)})
	for _, bad := range []string{"[]", `"x"`, "nope", `{"a":{"b":{"c":{"d":1}}}}`, `{"a":{"b":[1]}}`, string(big), string(euro)} {
		_, err := eventFields(nil, &bad)
		check(err != nil, "event fields: tags "+bad[:min(20, len(bad))]+" refused")
	}
	edge, _ := json.Marshal(map[string]string{"k": strings.Repeat("a", 4088)})
	_, err = eventFields(nil, str(string(edge)))
	check(err == nil, "event fields: 4096 bytes accepted")
	amp, _ := json.Marshal(map[string]string{"k": strings.Repeat("&", 4088)})
	_, err = eventFields(nil, str(string(amp)))
	check(err == nil, "event fields: & is not counted as an escape")
	check(missingValue([]string{"--tags"}) == "--tags" && missingValue([]string{"--intent", "i", "--linked-id"}) == "--linked-id" &&
		missingValue([]string{"--tags", "{}"}) == "" && missingValue(nil) == "", "flags without a value are refused")
	fmt.Printf("%d accept + %d reject cases, event-field cases, %d failed\n", len(v.Accept), len(v.Reject), fail)
	if fail > 0 {
		return 1
	}
	return 0
}
