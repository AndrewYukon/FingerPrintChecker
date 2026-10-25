# Publishing

Owner-only steps to publish every package in this repository. Nothing here runs in CI; CI only tests and builds
(`.github/workflows/packages.yml`).

Rules for every step below:

- Tokens live in files under `~/.config/fpchecker/` (mode 600). They are read into an environment variable of the one
  command that needs them. Never put a token on a command line, in a shell history, in a commit or in a log.
- Publish from a clean checkout of `main` at the commit CI was green on: `git status` empty, `git log -1` is that commit.
- A published version can never be changed or reused. Check twice, then publish.

## What is published

| Package | Registry | Name | Version | Source |
|---|---|---|---|---|
| Browser agent loader | npm | `@fpchecker/agent` | 0.1.0 | `web/agent` |
| React wrapper | npm | `@fpchecker/react` | 0.1.0 | `web/react` |
| Vue wrapper | npm | `@fpchecker/vue` | 0.1.0 | `web/vue` |
| Node.js server SDK | npm | `@fpchecker/node` | 0.1.0 | `server/node` |
| Python server SDK | PyPI | `fingerprintchecker` (import `fpchecker`) | 0.1.0 | `server/python` |
| Go server SDK | Go proxy (git tag) | `github.com/AndrewYukon/FingerPrintChecker/server/go` | v0.1.0 | `server/go` |
| Android SDK | Maven Central | `com.fpchecker:fpchecker-android` | 0.5.0 | `android/fpchecker` |
| Apple SDK | Swift Package Manager (git tag) | `https://github.com/AndrewYukon/FingerPrintChecker` | 0.5.0 | `apple/`, `Package.swift` |

## npm

### One-time setup

1. Create an npmjs.com account (with 2FA) and create the organization `fpchecker` (npmjs.com, avatar menu, "Add Organization",
   free plan). The scope `@fpchecker` is then yours.
2. Create a granular access token: npmjs.com, avatar menu, "Access Tokens", "Generate New Token", "Granular Access Token".
   Permissions "Read and write", packages scope "All packages" for the `fpchecker` organization (the packages do not exist yet,
   so they cannot be selected one by one), and a short expiry (30 days). If the account enforces 2FA for writes, enable
   "Bypass 2FA" on this token only.
3. Save it:

   ```bash
   mkdir -p ~/.config/fpchecker && chmod 700 ~/.config/fpchecker
   umask 077 && read -rs -p "npm token: " T && printf '%s' "$T" > ~/.config/fpchecker/npm-token; unset T; echo
   ```

### Checks before each package

Run these from the repository root.

```bash
npm ci && npm ci --prefix server/node
npm run build --workspace web/agent                 # the wrappers need the agent's dist
npm test --workspace web/agent --workspace web/react --workspace web/vue
(cd server/node && npm test)
```

For the package you are about to publish (`web/agent` is the example):

1. Version fields. `grep '"version"' web/agent/package.json`, and for react and vue also the dependency on the agent:
   `grep '@fpchecker/agent' web/react/package.json web/vue/package.json` must be a range the published agent satisfies
   (`^0.1.0` matches 0.1.0). `npm view @fpchecker/<name> version` must say "not found" (first publish) or an older version.
2. Vendor provenance (agent only). `head -c 300 web/agent/vendor/fp-agent.min.js` must show the source commit and version in its first
   line comment, and the file must be the unmodified copy of the agent that fpchecker.com serves:
   `curl -s https://fpchecker.com/static/fp-agent.min.js | shasum -a 256` against `shasum -a 256 web/agent/vendor/fp-agent.min.js`.
   They may differ if the website has moved on; in that case the comment's commit is the proof, and it must name a commit that exists.
3. Contents. `npm pack --dry-run --workspace web/agent 2>&1 | tail -30` lists exactly `dist/`, `vendor/`, `README.md`, `package.json`
   (react and vue: `dist/`, `README.md`; node: `dist/`, `README.md`, `LICENSE`). No `src/`, no `test/`, no `.env`, no `node_modules`.
   `prepack` rebuilds the package, so the listed `dist/` is fresh.

### Publish, in this order

The wrappers depend on the agent, so the agent must exist on the registry first. `@fpchecker/node` is independent and goes last.

1. `@fpchecker/agent`
2. `@fpchecker/react` and `@fpchecker/vue` (either order)
3. `@fpchecker/node`

Publish with a temporary npmrc that reads the token from the environment, so the token is never on the command line:

```bash
NPMRC="$(mktemp)" && chmod 600 "$NPMRC"
printf '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}\n' > "$NPMRC"   # literal ${...}: npm expands it

publish() {   # usage: publish <dir> [workspace-flag]
  ( export NODE_AUTH_TOKEN="$(cat ~/.config/fpchecker/npm-token)"
    cd "$1" && npm publish --access public --userconfig "$NPMRC" )
}

publish web/agent
publish web/react
publish web/vue
publish server/node

rm -f "$NPMRC"
```

If npm asks for a one-time password, the token was not created with "Bypass 2FA"; create a new one rather than typing codes into scripts.

Verify: `npm view @fpchecker/agent version` (and react, vue, node) prints `0.1.0`; then in an empty directory
`npm install @fpchecker/react` succeeds.

### Next version

Bump `version` in the package's `package.json` (and the agent range in react and vue if the agent had a breaking change),
commit, wait for CI, then repeat the checks and the publish for the changed packages only, still agent first.

## PyPI (`fingerprintchecker`)

PyPI refused `fpchecker` as too similar to the existing `fp-checker`; the distribution is `fingerprintchecker`, the import name stays `fpchecker`.

### One-time setup

1. Create an account on pypi.org (with 2FA). Optionally do the same on test.pypi.org to rehearse.
2. Account settings, "API tokens", "Add API token", scope "Entire account" (the project does not exist yet; after the first upload,
   replace it with a token scoped to the `fpchecker` project).
3. Save it:

   ```bash
   umask 077 && read -rs -p "pypi token: " T && printf '%s' "$T" > ~/.config/fpchecker/pypi-token; unset T; echo
   ```

### Checks and upload

```bash
cd server/python
grep '^version' pyproject.toml                        # 0.1.0; PyPI refuses a version that already exists
python3 -m venv /tmp/pypi-venv && . /tmp/pypi-venv/bin/activate
python -m pip install -q build twine pytest "cryptography>=41" && python -m pip install -q -e . && python -m pytest -q
rm -rf dist && python -m build                        # writes dist/*.tar.gz and dist/*.whl
python -m twine check dist/*
tar tzf dist/fingerprintchecker-*.tar.gz | head -30            # sources, README.md, LICENSE; no .env

TWINE_USERNAME=__token__ TWINE_PASSWORD="$(cat ~/.config/fpchecker/pypi-token)" python -m twine upload dist/*
```

(`TWINE_PASSWORD="$(cat ...)"` sets an environment variable for that one process; it is not an argument of `twine`.)

Verify in a fresh venv: `pip install fingerprintchecker==0.1.0 && python -c "import fpchecker; print(fpchecker)"`.

## Go (`server/go`)

The Go module lives in a subdirectory, so its git tag must carry the directory prefix: the tag for module version `v0.1.0` is
`server/go/v0.1.0`. There is no token and no upload; pushing the tag is the release.

```bash
git switch main && git pull --ff-only
(cd server/go && go vet ./... && go test ./... && test -z "$(gofmt -l .)")
git tag server/go/v0.1.0
git push origin server/go/v0.1.0
```

Verify through the public proxy (it can take a minute for a new tag to appear):

```bash
GOPROXY=https://proxy.golang.org go list -m github.com/AndrewYukon/FingerPrintChecker/server/go@v0.1.0
```

If you asked the proxy for the version before the tag was pushed, it may cache the miss; retry after a few minutes.

## Android (Maven Central) and Apple (Swift Package Manager), SDK 0.5.0

This repository documents no step-by-step release procedure for these; what exists is the build configuration. Use it as follows.

Both SDKs are already at 0.5.0 in the source: `android/fpchecker/build.gradle.kts` (`val sdkVersion`) and
`apple/Sources/FingerPrintChecker/Version.swift` (`FPVersion.sdk`). The demo apps have their own versions; leave them.

**Android.** `android/fpchecker/build.gradle.kts` uses the `com.vanniktech.maven.publish` plugin, publishes to Maven Central through
the Central Portal (`SonatypeHost.CENTRAL_PORTAL`) under `com.fpchecker:fpchecker-android`, and signs when a signing key is provided
(`signingInMemoryKey` project property, or the classic `signing.*` properties). The credentials used for the earlier releases
(0.1.0 to 0.4.0) are in `~/.config/fpchecker/android/publish.properties`: each `key=value` line goes in as an
`ORG_GRADLE_PROJECT_<key>` environment variable, never as a `-P` argument and never echoed. JDK 17:

```bash
cd android
export JAVA_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || echo /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home)"
./gradlew :fpchecker:testDebugUnitTest
# export the properties without printing them
while IFS='=' read -r k v; do
  case "$k" in ''|'#'*) continue ;; esac
  export "ORG_GRADLE_PROJECT_${k}=${v}"
done < ~/.config/fpchecker/android/publish.properties
./gradlew :fpchecker:publishAndReleaseToMavenCentral
```

The task can finish without printing anything useful; confirm at
`https://repo1.maven.org/maven2/com/fpchecker/fpchecker-android/0.5.0/fpchecker-android-0.5.0.pom` (expect 200; it can take up to an
hour). If it is still 404 after an hour, open the deployment at central.sonatype.com.

**Apple.** Swift Package Manager reads the git tag, nothing else. After CI is green on `main`:

```bash
swift test
git tag 0.5.0 && git push origin 0.5.0
```

The existing tags are plain versions without a prefix (`0.1.0` ... `0.4.0`). Verify in an empty package:
`.package(url: "https://github.com/AndrewYukon/FingerPrintChecker", from: "0.5.0")` resolves.

## After publishing

In `fpchecker-web`, flip the `PACKAGES_PUBLISHED` flag so the website stops saying "install from GitHub" and shows the registry
install commands. Then update the "install from GitHub until published" note in `README.md` and its translations in this repository.
