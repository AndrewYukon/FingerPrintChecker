"""fpchecker CLI identify (Python 3.8+, stdlib only). Env: FPC_PK, FPC_SEAL, FPC_TENANT, FPC_BASE, FPC_POW (default 16)."""
import hashlib, hmac, json, os, pathlib, platform, re, subprocess, urllib.request, uuid

env = os.environ.get
base, pk, bits = env("FPC_BASE", "https://api.fpchecker.com"), env("FPC_PK"), int(env("FPC_POW", "16"))
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
    with urllib.request.urlopen(req, timeout=10) as r: return json.load(r)
nonce = call(f"/v1/challenge?difficulty={bits}")["nonce"]
pow_ = 0
while int.from_bytes(hashlib.sha256(f"{nonce}:{pow_}".encode()).digest(), "big") >> (256 - bits): pow_ += 1
canonical = nonce + "|" + "|".join(sorted(f"{c['key']}={c['value']}" for c in components))  # sort the key=value strings
sig = hmac.new(env("FPC_SEAL").encode(), canonical.encode(), hashlib.sha256).hexdigest()
print(json.dumps(call("/v1/identify", {"platform": "cli", "nonce": nonce, "sig": sig, "components": components, "agentVersion": "cli-python-1", "pow": str(pow_)}), indent=2))
