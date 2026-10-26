# FingerPrintChecker Cloudflare Worker

Serve the FingerPrintChecker agent and its API from your own domain. It catches the same things as the standard setup, but the browser only talks to your site, so ad blockers and privacy extensions have nothing third-party to block, and your server still sees the real visitor IP, country, timezone, city and network.

## Install

You need a Cloudflare account with your site on it, and a proxy secret created in the FingerPrintChecker console (project settings, proxy integration). The secret is shown once.

### Option 1: Deploy to Cloudflare button

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/AndrewYukon/FingerPrintChecker/tree/main/integrations/cloudflare-worker)

Then set the secret (below) and add the route.

### Option 2: wrangler

```bash
git clone https://github.com/AndrewYukon/FingerPrintChecker.git
cd FingerPrintChecker/integrations/cloudflare-worker
npm install
npx wrangler secret put FPC_PROXY_SECRET   # paste the secret from the console
npx wrangler deploy
```

### Route

Add the route `yoursite.com/fpc/*` to the Worker (Workers & Pages, your worker, Settings, Domains & Routes), or uncomment `routes` in `wrangler.toml`.

## Agent snippet

```js
import { load } from '@fingerprintchecker/agent';

const fp = await load({
  endpoint: 'https://yoursite.com/fpc',
  scriptUrl: 'https://yoursite.com/fpc/agent.js',
});
```

## Configuration

| Name | Kind | Default | Purpose |
|---|---|---|---|
| `FPC_PROXY_SECRET` | secret, required | none | Proves to FingerPrintChecker that requests come from your Worker. Without it the Worker answers 500 and forwards nothing. |
| `FPC_PATH` | var | `fpc` | Path prefix on your domain. |
| `FPC_API` | var | `https://api.fpchecker.com` | API origin. |
| `FPC_AGENT_URL` | var | `https://fpchecker.com/static/fp-agent.min.js` | Where `agent.js` is fetched from (cached for one hour). |

## What the Worker serves

Only these paths, everything else is 404:

- `/<path>/agent.js`
- `/<path>/v1/challenge`, `/<path>/v1/identify`
- `/<path>/v2/challenge`, `/<path>/v2/identify`

## What it forwards

- Method, body, `Origin` and `X-Publishable-Key` are passed through unchanged.
- Added headers: `X-FPC-Proxy-Secret`, `X-FPC-Client-IP` (from `CF-Connecting-IP`), `X-FPC-Client-Country`, `X-FPC-Client-Timezone`, `X-FPC-Client-City`, `X-FPC-Client-ASN` (from Cloudflare's request data) and `X-FPC-Forwarded-Host`. Headers the Worker cannot determine are left out.
- `X-FPC-Client-City` is percent-encoded with `encodeURIComponent` because city names can be non-ASCII; the server decodes it.
- Any `X-FPC-*` header sent by the browser is removed first, so a visitor cannot pre-set these values.
- Cookies are never forwarded: `Cookie` is dropped on the way up and `Set-Cookie` on the way down.

## Development

```bash
npm install
npm run typecheck
npm test
```
