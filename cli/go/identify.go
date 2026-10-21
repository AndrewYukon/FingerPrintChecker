// fpchecker CLI identify (Go 1.21+, stdlib only). Env: FPC_PK, FPC_SEAL, FPC_TENANT, FPC_BASE, FPC_POW (default 16).
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	base, pk, nbits := env("FPC_BASE", "https://api.fpchecker.com"), os.Getenv("FPC_PK"), env("FPC_POW", "16")
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
	nonce := call("GET", "/v1/challenge?difficulty="+nbits, nil)["nonce"].(string)
	need, _ := strconv.Atoi(nbits)
	pow := 0
	for ; ; pow++ {
		d := sha256.Sum256([]byte(nonce + ":" + strconv.Itoa(pow)))
		z := 0
		for _, x := range d {
			z += bits.LeadingZeros8(x)
			if x != 0 {
				break
			}
		}
		if z >= need {
			break
		}
	}
	parts := []string{}
	for _, c := range comps {
		parts = append(parts, c["key"]+"="+c["value"])
	}
	sort.Strings(parts) // sort the key=value strings
	mac := hmac.New(sha256.New, []byte(os.Getenv("FPC_SEAL")))
	mac.Write([]byte(nonce + "|" + strings.Join(parts, "|")))
	out, _ := json.MarshalIndent(call("POST", "/v1/identify", map[string]any{"platform": "cli", "nonce": nonce, "sig": hex.EncodeToString(mac.Sum(nil)), "components": comps, "agentVersion": "cli-go-1", "pow": strconv.Itoa(pow)}), "", "  ")
	fmt.Println(string(out))
}
