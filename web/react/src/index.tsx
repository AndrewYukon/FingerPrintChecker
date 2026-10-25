'use client';

import { load } from '@fpchecker/agent';
import type { FpAgent, IdentifyOptions, IdentifyResult, LoadOptions } from '@fpchecker/agent';
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

export type { IdentifyOptions, IdentifyResult, LoadOptions } from '@fpchecker/agent';

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

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const getAgent = useCallback((): Promise<FpAgent> => {
    const key = JSON.stringify([publishableKey, endpoint ?? null, scriptUrl ?? null]);
    if (agentRef.current?.key !== key) {
      const opts: LoadOptions = {
        publishableKey,
        ...(endpoint !== undefined ? { endpoint } : {}),
        ...(scriptUrl !== undefined ? { scriptUrl } : {}),
      };
      agentRef.current = { key, promise: load(opts) };
    }
    return agentRef.current.promise;
  }, [publishableKey, endpoint, scriptUrl]);

  // Client only: effects never run during server rendering.
  useEffect(() => {
    getAgent().catch((e: unknown) => {
      if (mounted.current) setError(toError(e));
    });
  }, [getAgent]);

  const identify = useCallback(
    async (opts: IdentifyOptions): Promise<IdentifyResult> => {
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
        const err = toError(e);
        if (isLatest()) setError(err);
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
