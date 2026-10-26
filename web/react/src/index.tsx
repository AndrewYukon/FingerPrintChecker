'use client';

import { FpCheckerAgentError, load } from '@fingerprintchecker/agent';
import type { FpAgent, IdentifyOptions, IdentifyResult, LoadOptions } from '@fingerprintchecker/agent';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

export type { IdentifyOptions, IdentifyResult, LoadOptions } from '@fingerprintchecker/agent';

export interface FpCheckerState {
  identify(opts: IdentifyOptions): Promise<IdentifyResult>;
  data?: IdentifyResult;
  error?: Error;
  isLoading: boolean;
}

export type FpCheckerProviderProps = LoadOptions & { children?: ReactNode };

const FpCheckerContext = createContext<FpCheckerState | null>(null);

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

export function FpCheckerProvider(props: FpCheckerProviderProps) {
  const { publishableKey, endpoint, scriptUrl, children } = props;
  const [data, setData] = useState<IdentifyResult | undefined>(undefined);
  const [error, setError] = useState<Error | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(false);

  const mounted = useRef(true);
  const callId = useRef(0);
  const agentRef = useRef<{ key: string; promise: Promise<FpAgent> } | null>(null);
  const prevKey = useRef<string | null>(null);
  const optionsKey = JSON.stringify([publishableKey, endpoint ?? null, scriptUrl ?? null]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const getAgent = useCallback((): Promise<FpAgent> => {
    if (agentRef.current?.key !== optionsKey) {
      const opts: LoadOptions = {
        publishableKey,
        ...(endpoint !== undefined ? { endpoint } : {}),
        ...(scriptUrl !== undefined ? { scriptUrl } : {}),
      };
      const promise = load(opts);
      agentRef.current = { key: optionsKey, promise };
      // Do not cache a failed load: the next identify retries.
      promise.catch(() => {
        if (agentRef.current?.promise === promise) agentRef.current = null;
      });
    }
    return agentRef.current.promise;
  }, [optionsKey, publishableKey, endpoint, scriptUrl]);

  // Client only: effects never run during server rendering.
  // A change of options starts a new generation: old calls become stale and state resets.
  useEffect(() => {
    let active = true;
    // Only a real change resets: on first mount (and the StrictMode re-run) children's
    // mount-time identify calls have already started and must stay current.
    if (prevKey.current !== null && prevKey.current !== optionsKey) {
      callId.current += 1;
      setData(undefined);
      setError(undefined);
      setIsLoading(false);
    }
    prevKey.current = optionsKey;
    getAgent().catch((e: unknown) => {
      if (active) setError(toError(e));
    });
    return () => {
      active = false;
    };
  }, [getAgent, optionsKey]);

  const identify = useCallback(
    async (opts: IdentifyOptions): Promise<IdentifyResult> => {
      if (typeof window === 'undefined') {
        throw new FpCheckerAgentError('ssr', 'identify() can only run in the browser; call it from an event handler or effect.');
      }
      const id = ++callId.current;
      const isLatest = () => mounted.current && callId.current === id;
      setIsLoading(true);
      try {
        const agent = await getAgent();
        const result = await agent.identify(opts);
        if (isLatest()) {
          setData(result);
          setError(undefined);
        }
        return result;
      } catch (e) {
        if (isLatest()) setError(toError(e));
        throw e;
      } finally {
        if (isLatest()) setIsLoading(false);
      }
    },
    [getAgent],
  );

  const value = useMemo<FpCheckerState>(
    () => ({
      identify,
      isLoading,
      ...(data !== undefined ? { data } : {}),
      ...(error !== undefined ? { error } : {}),
    }),
    [identify, data, error, isLoading],
  );

  return <FpCheckerContext.Provider value={value}>{children}</FpCheckerContext.Provider>;
}

export function useFpChecker(): FpCheckerState {
  const ctx = useContext(FpCheckerContext);
  if (!ctx) {
    throw new Error('useFpChecker must be used inside <FpCheckerProvider>. Wrap your app (or layout) with it.');
  }
  return ctx;
}
