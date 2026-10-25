"""fpchecker CLI identify (Python 3.8+, stdlib only). Env: FPC_PK, FPC_INTENT (v2) or FPC_SEAL (v1), FPC_TENANT, FPC_BASE, FPC_POW (default 16).
v2 (recommended): python3 identify.py --intent <intentToken>   (your backend mints it with POST /v2/intents). v1: needs FPC_SEAL.
Optional event fields: --linked-id <id> (1-256 chars, no control chars) and --tags '<json object>' (<= 4096 bytes, nested <= 3 levels, an array counts as a level).
They sit beside the signed fields; the answer's eventId identifies the event. Bad values exit 2 before any request.
Self-test: python3 identify.py --self-test   (checks ../../test-vectors/protocol-v2.json and the event-field rules)"""
import base64, math, hashlib, hmac, json, os, pathlib, platform, re, subprocess, sys, urllib.error, urllib.parse, urllib.request, uuid

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

def _within_depth(v, depth):
    if isinstance(v, list): return depth < 3 and all(_within_depth(x, depth + 1) for x in v)
    if isinstance(v, dict): return depth <= 3 and all(_within_depth(x, depth + 1) for x in v.values())
    return True

def _finite(v):  # 1e400 parses to inf, which JSON.parse on the server never sees as a number
    if isinstance(v, float): return math.isfinite(v)
    if isinstance(v, list): return all(_finite(x) for x in v)
    if isinstance(v, dict): return all(_finite(x) for x in v.values())
    return True

def event_fields(linked_id=None, tags_json=None):
    """The body fragment for the optional event fields ({} when neither is given); raises ValueError on a bad value. Never part of the signed bytes."""
    out = {}
    if linked_id is not None:
        if not (1 <= len(linked_id.encode("utf-16-le")) // 2 <= 256) or re.search("[\x00-\x1f\x7f]", linked_id): raise ValueError("invalid linkedId: 1-256 characters, no control characters")
        out["linkedId"] = linked_id
    if tags_json is not None:
        def no_const(c): raise ValueError(c)  # NaN / Infinity are not JSON
        try: tags = json.loads(tags_json, parse_constant=no_const)
        except ValueError: raise ValueError("invalid tags: not valid JSON") from None
        if tags is not None:  # null means "not set", as on the server
            if not isinstance(tags, dict) or not _finite(tags) or not _within_depth(tags, 1) or len(json.dumps(tags, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 4096:
                raise ValueError("invalid tags: a JSON object of at most 4096 bytes, nested at most 3 levels (an array counts as a level)")
            out["tags"] = tags
    return out

def flag_value(args, name):
    """The value after `name`, None when the flag is absent; a flag with no value is a usage error (ValueError)."""
    if name not in args: return None
    i = args.index(name) + 1
    if i >= len(args): raise ValueError(f"{name} needs a value")
    return args[i]

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
    def refused(*a):
        try: event_fields(*a); return False
        except ValueError: return True
    check(event_fields() == {} and event_fields(None, "null") == {}, "event fields: absent / null send nothing")
    check(event_fields("o_1", '{"a":{"b":{"c":1}},"l":[1]}') == {"linkedId": "o_1", "tags": {"a": {"b": {"c": 1}}, "l": [1]}}, "event fields: valid")
    check(len(event_fields("a" * 256)["linkedId"]) == 256, "event fields: 256 chars")
    for bad in ["", "a" * 257, "a\nb", "a\x7fb"]: check(refused(bad, None), f"event fields: linkedId {bad[:8]!r} refused")
    for bad in ["[]", '"x"', "nope", '{"x":NaN}', '{"a":{"b":{"c":{"d":1}}}}', '{"a":{"b":[1]}}', json.dumps({"k": "a" * 4096}), json.dumps({"k": "\u20ac" * 1366}, ensure_ascii=False)]:
        check(refused(None, bad), f"event fields: tags {bad[:20]} refused")
    check(refused(None, '{"x":1e400}') and refused(None, '{"x":[-1e400]}'), "event fields: non-finite numbers refused")
    check(not refused(None, json.dumps({"k": "a" * 4088})), "event fields: 4096 bytes accepted")
    for flag in ("--linked-id", "--tags"):
        try: flag_value(["--intent", "i", flag], flag); check(False, f"{flag} without a value must be refused")
        except ValueError: pass
    check(flag_value(["--tags", "{}"], "--tags") == "{}" and flag_value([], "--tags") is None, "flag_value")
    print(f"{len(v['accept'])} accept + {len(v['reject'])} reject cases, event-field cases, {fail} failed")
    sys.exit(1 if fail else 0)

def main():
    env, args = os.environ.get, sys.argv[1:]
    base, pk, bits = env("FPC_BASE", "https://api.fpchecker.com"), env("FPC_PK"), int(env("FPC_POW", "16"))
    try: intent = flag_value(args, "--intent") or env("FPC_INTENT")
    except ValueError as e: print(e, file=sys.stderr); sys.exit(2)
    try: fields = event_fields(flag_value(args, "--linked-id"), flag_value(args, "--tags"))
    except ValueError as e: print(e, file=sys.stderr); sys.exit(2)  # before any request
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
        agent = "cli-python-0.4.0"
        identify_canonical("cli", agent, ch["challenge"], components)  # refuse locally what the server refuses
        out = call("/v2/identify", {"protocolVersion": 2, "platform": "cli", "intentToken": intent, "challenge": ch["challenge"], "agentVersion": agent, "components": components, "pow": solve(ch["challenge"]), **fields})
        print(json.dumps(out, indent=2))  # hand `attestation` to your backend for /v1/eligibility
        if out.get("ok") is not True or not isinstance(out.get("attestation"), str) or not out["attestation"]: sys.exit(1)  # success without attestation = failure
        return
    nonce = call(f"/v1/challenge?difficulty={bits}")["nonce"]
    canonical = nonce + "|" + "|".join(sorted(f"{c['key']}={c['value']}" for c in components))  # sort the key=value strings
    sig = hmac.new(env("FPC_SEAL").encode(), canonical.encode(), hashlib.sha256).hexdigest()
    print(json.dumps(call("/v1/identify", {"platform": "cli", "nonce": nonce, "sig": sig, "components": components, "agentVersion": "cli-python-1", "pow": solve(nonce), **fields}), indent=2))

if __name__ == "__main__":
    if "--self-test" in sys.argv: self_test()
    main()
