# @fingerprintchecker/react

React provider and hook for [FingerPrintChecker](https://fpchecker.com). Built on `@fingerprintchecker/agent`. Requires React 18 or newer.

```bash
npm install @fingerprintchecker/react
```

```tsx
import { FpCheckerProvider, useFpChecker } from '@fingerprintchecker/react';

<FpCheckerProvider publishableKey="pk_live_...">
  <App />
</FpCheckerProvider>
```

The provider accepts the same options as `load()` from `@fingerprintchecker/agent`: `publishableKey`, optional `endpoint`, optional `scriptUrl`. The agent loads in the browser after mount; nothing loads during server rendering.

```tsx
const { identify, data, error, isLoading } = useFpChecker();
const result = await identify({ intentToken, linkedId, cache: { ttlSeconds: 60, storage: 'session' } });
```

- `identify(opts)` passes through to the agent, updates `data`, `error`, `isLoading`, returns the result and rethrows on failure.
- If several calls overlap, the most recently started call decides `data`.
- A failure to load the agent shows up as `error`.
- `useFpChecker()` outside the provider throws an error naming `FpCheckerProvider`.

## Next.js App Router

The package files start with `'use client'`, so they can be imported from client components.

```tsx
// app/fp-provider.tsx
'use client';
import { FpCheckerProvider } from '@fingerprintchecker/react';

export function Providers({ children }: { children: React.ReactNode }) {
  return <FpCheckerProvider publishableKey={process.env.NEXT_PUBLIC_FPCHECKER_KEY!}>{children}</FpCheckerProvider>;
}
```

```tsx
// app/layout.tsx  (server component)
import { Providers } from './fp-provider';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

```tsx
// app/signup/signup-button.tsx
'use client';
import { useFpChecker } from '@fingerprintchecker/react';

export function SignupButton({ intentToken }: { intentToken: string }) {
  const { identify, isLoading, error } = useFpChecker();

  async function onClick() {
    const result = await identify({ intentToken });
    // Send the result to YOUR backend, which verifies it with the server SDK.
    await fetch('/api/signup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ eventId: result.eventId, sealedResult: result.sealedResult }),
    });
  }

  return (
    <>
      <button onClick={onClick} disabled={isLoading}>Sign up</button>
      {error && <p role="alert">{error.message}</p>}
    </>
  );
}
```

Call `identify` from a handler, not during render.

## License

Apache-2.0
