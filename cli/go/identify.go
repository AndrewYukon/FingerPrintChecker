// fpchecker CLI identify (Go 1.21+, stdlib only). Env: FPC_PK, FPC_INTENT (v2) or FPC_SEAL (v1), FPC_TENANT, FPC_BASE, FPC_POW (default 16).
// v2 (recommended): go run identify.go --intent <intentToken>   (your backend mints it with POST /v2/intents). v1: needs FPC_SEAL.
// Self-test: go run identify.go --self-test   (checks ../../test-vectors/protocol-v2.json)
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
	for i, a := range args {
		if a == "--intent" && i+1 < len(args) {
			intent = args[i+1]
		}
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
		const agent = "cli-go-0.3.0"
		if _, err := identifyCanonical("cli", agent, challenge, comps); err != nil { // refuse locally what the server refuses
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		answer := call("POST", "/v2/identify", map[string]any{"protocolVersion": 2, "platform": "cli", "intentToken": intent, "challenge": challenge, "agentVersion": agent, "components": comps, "pow": solve(challenge, need)})
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
	out, _ := json.MarshalIndent(call("POST", "/v1/identify", map[string]any{"platform": "cli", "nonce": nonce, "sig": hex.EncodeToString(mac.Sum(nil)), "components": comps, "agentVersion": "cli-go-1", "pow": solve(nonce, need)}), "", "  ")
	fmt.Println(string(out))
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
	fmt.Printf("%d accept + %d reject cases, %d failed\n", len(v.Accept), len(v.Reject), fail)
	if fail > 0 {
		return 1
	}
	return 0
}
