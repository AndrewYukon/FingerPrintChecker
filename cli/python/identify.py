"""fpchecker CLI identify (Python 3.8+, stdlib only). Env: FPC_PK, FPC_INTENT (v2) or FPC_SEAL (v1), FPC_TENANT, FPC_BASE, FPC_POW (default 16).
v2 (recommended): python3 identify.py --intent <intentToken>   (your backend mints it with POST /v2/intents). v1: needs FPC_SEAL.
Self-test: python3 identify.py --self-test   (checks ../../test-vectors/protocol-v2.json)"""
import base64, hashlib, hmac, json, os, pathlib, platform, re, subprocess, sys, urllib.error, urllib.parse, urllib.request, uuid

KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}

def jcs_string(s):  # RFC 8785 string, written by hand: lower-case \u00xx for other controls, everything else raw
    if not isinstance(s, str) or re.search("[\ud800-\udfff]", s): raise ValueError("string is not well-formed UTF-16")
    return '"' + "".join(ESCAPES.get(ch) or (f"\\u{ord(ch):04x}" if ord(ch) < 0x20 else ch) for ch in s) + '"'

def utf16_key(s): return s.encode("utf-16-be")  # big-endian bytes compare as UTF-16 code units

def identify_canonical(platform_, agent_version, challenge, components):
    if not isinstance(agent_version, str) or len(agent_version.encode("utf-16-le")) // 2 > 64: raise ValueError("bad agentVersion")
    seen = set()
    for c in components:
        if not KEY_RE.match(c["key"]): raise ValueError(f"bad component key: {c['key']}")
        if c["key"] in seen: raise ValueError(f"duplicate component key: {c['key']}")
        seen.add(c["key"])
    comps = ",".join("{" + (f'"hash":{jcs_string(c["hash"])},' if "hash" in c else "") + f'"key":{jcs_string(c["key"])},"value":{jcs_string(c["value"])}' + "}"
                     for c in sorted(components, key=lambda c: utf16_key(c["key"])))
    return (f'{{"agentVersion":{jcs_string(agent_version)},"challenge":{jcs_string(challenge)},"components":[{comps}],'
            f'"domain":"fpchecker.identify.v2","platform":{jcs_string(platform_)},"protocolVersion":2}}')

def self_test():
    v = json.loads((pathlib.Path(__file__).resolve().parents[2] / "test-vectors" / "protocol-v2.json").read_text(encoding="utf-8"))
    fail = 0
    def check(ok, msg):
        nonlocal fail
        if not ok: fail += 1; print("FAIL " + msg, file=sys.stderr)
    for a in v["accept"]:
        i = a["input"]
        try: canonical = identify_canonical(i["platform"], i["agentVersion"], i["challenge"], i["components"])
        except ValueError as e: check(False, f"{a['name']}: {e}"); continue
        digest = hashlib.sha256(canonical.encode("utf-8")).digest()
        check(canonical == a["canonical"], a["name"] + ": canonical")
        check(digest.hex() == a["requestBindingHex"], a["name"] + ": requestBindingHex")
        check(base64.b64encode(digest).decode() == a["clientDataHashBase64"], a["name"] + ": clientDataHashBase64")
    for r in v["reject"]:
        i = r["input"]
        try: identify_canonical(i["platform"], i["agentVersion"], i["challenge"], i["components"]); check(False, r["name"] + ": must be refused")
        except ValueError: pass
    print(f"{len(v['accept'])} accept + {len(v['reject'])} reject cases, {fail} failed")
    sys.exit(1 if fail else 0)

def main():
    env, args = os.environ.get, sys.argv[1:]
    base, pk, bits = env("FPC_BASE", "https://api.fpchecker.com"), env("FPC_PK"), int(env("FPC_POW", "16"))
    intent = args[args.index("--intent") + 1] if "--intent" in args else env("FPC_INTENT")
    if not pk: sys.exit("FPC_PK is not set")
    if not intent and not env("FPC_SEAL"): sys.exit("give --intent <intentToken> (or FPC_INTENT) for v2, or FPC_SEAL for v1")
    id_file = pathlib.Path.home() / ".config" / env("FPC_TENANT", "fpchecker") / "device-id"
    if not id_file.exists():
        id_file.parent.mkdir(parents=True, exist_ok=True)
        id_file.write_text(str(uuid.uuid4())); id_file.chmod(0o600)
    zone = re.search(r"zoneinfo/(.+)$", os.path.realpath("/etc/localtime"))  # IANA name, e.g. Europe/Berlin
    components = [{"key": "cli.randomId", "value": id_file.read_text().strip()}, {"key": "cli.osVersion", "value": platform.release()[:32]}]
    if zone: components.append({"key": "cli.timezone", "value": zone.group(1)})
    try:  # macOS hardware UUID; elsewhere only the random id is sent
        m = re.search(r'"IOPlatformUUID" = "([0-9A-F-]{36})"', subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], capture_output=True, text=True).stdout)
        if m: components.append({"key": "cli.platformUuid", "value": m.group(1)})
    except OSError: pass
    def call(path, body=None):
        req = urllib.request.Request(base + path, data=body and json.dumps(body).encode(), headers={"content-type": "application/json", "x-publishable-key": pk, "user-agent": "fpchecker-cli-python/1"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r: return json.load(r)
        except urllib.error.HTTPError as e: return json.load(e)  # failures carry {ok:false, ...}
    def solve(challenge):
        pow_ = 0
        while int.from_bytes(hashlib.sha256(f"{challenge}:{pow_}".encode()).digest(), "big") >> (256 - bits): pow_ += 1
        return str(pow_)
    if intent:  # v2: nothing is sealed or bound; the answer carries an opaque attestation
        ch = call(f"/v2/challenge?intent={urllib.parse.quote(intent, safe='')}&difficulty={bits}")
        if not ch.get("ok") or not isinstance(ch.get("challenge"), str): print(json.dumps(ch, indent=2)); sys.exit(1)
        agent = "cli-python-0.2.0"
        identify_canonical("cli", agent, ch["challenge"], components)  # refuse locally what the server refuses
        out = call("/v2/identify", {"protocolVersion": 2, "platform": "cli", "intentToken": intent, "challenge": ch["challenge"], "agentVersion": agent, "components": components, "pow": solve(ch["challenge"])})
        print(json.dumps(out, indent=2))  # hand `attestation` to your backend for /v1/eligibility
        if out.get("ok") is not True or not isinstance(out.get("attestation"), str) or not out["attestation"]: sys.exit(1)  # success without attestation = failure
        return
    nonce = call(f"/v1/challenge?difficulty={bits}")["nonce"]
    canonical = nonce + "|" + "|".join(sorted(f"{c['key']}={c['value']}" for c in components))  # sort the key=value strings
    sig = hmac.new(env("FPC_SEAL").encode(), canonical.encode(), hashlib.sha256).hexdigest()
    print(json.dumps(call("/v1/identify", {"platform": "cli", "nonce": nonce, "sig": sig, "components": components, "agentVersion": "cli-python-1", "pow": solve(nonce)}), indent=2))

if __name__ == "__main__":
    if "--self-test" in sys.argv: self_test()
    main()
