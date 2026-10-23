# Command-line tools

A CLI is not an app bundle: no App Attest, no DeviceCheck, no Play Integrity, and it may be
written in any language. So there is no library here — only the protocol and three small,
dependency-free examples that produce the same `c4_` device id on the same machine:

| File | Runtime |
|---|---|
| [`node/identify.mjs`](node/identify.mjs) | Node 18+ |
| [`python/identify.py`](python/identify.py) | Python 3.8+ |
| [`go/identify.go`](go/identify.go) | Go 1.21+ (`go run identify.go`) |

**Protocol v2 (recommended).** Your backend mints an intent with its secret key (`POST /v2/intents`, see
[PROTOCOL-V2.md](../PROTOCOL-V2.md)) and gives the CLI the token. No seal key is needed and nothing is bound or sealed:

```sh
export FPC_PK=pk_...          # publishable key
export FPC_TENANT=yourapp     # the random id is kept in ~/.config/$FPC_TENANT/device-id
node cli/node/identify.mjs --intent "$INTENT_TOKEN"     # or export FPC_INTENT=...
python3 cli/python/identify.py --intent "$INTENT_TOKEN"
(cd cli/go && go run identify.go --intent "$INTENT_TOKEN")
```

The answer is `{ ok, protocolVersion: 2, attestation }`; send `attestation` to your backend. The CLIs exit non-zero when
the answer is a failure or has no `attestation`. Each one has its own JCS serializer and a self-test that checks every
case in [`test-vectors/protocol-v2.json`](../test-vectors/protocol-v2.json):

```sh
node cli/node/identify.mjs --self-test
python3 cli/python/identify.py --self-test
(cd cli/go && go run identify.go --self-test)
```

**Protocol v1** (when `--intent` and `FPC_INTENT` are absent): needs the seal key.

```sh
export FPC_PK=pk_...          # publishable key
export FPC_SEAL=...           # seal key (console → project)
node cli/node/identify.mjs    # prints the identify answer; send `attestation` to your backend
```

What they send (see [PROTOCOL.md](../PROTOCOL.md)): `cli.randomId` (a UUID generated once and kept
in `~/.config/<tenant>/device-id`, mode 0600), `cli.platformUuid` on macOS (`IOPlatformUUID` from
`ioreg`, which survives reinstalls), `cli.timezone` and `cli.osVersion`.

**CLI devices are never attested.** Enable `cli` in the project's native platforms, and set the
project's human verification to **PoW** (or "either"): a terminal cannot solve Turnstile. The
examples solve a 16-bit proof of work (`FPC_POW`, 8–28) so that a first claim can pass; your
backend still decides with `/v1/eligibility`, and should add its own proof (e-mail verification)
for anything valuable.
