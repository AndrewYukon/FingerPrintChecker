import { act, cleanup, render, renderHook, waitFor } from '@testing-library/react';
import { renderToString } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { StrictMode, useEffect, type ReactNode } from 'react';

const identifyMock = vi.fn();
const loadMock = vi.fn();
vi.mock('@fpchecker/agent', async (orig) => ({
  ...(await orig<typeof import('@fpchecker/agent')>()),
  load: (o: unknown) => loadMock(o),
}));

// Observe every state-setter call: React 18 no longer warns on setState after unmount,
// so the only way to see the unmount guard is to count setter calls.
const setterCalls = vi.hoisted(() => ({ count: 0 }));
vi.mock('react', async (orig) => {
  const actual = await orig<typeof import('react')>();
  return {
    ...actual,
    useState: (init: unknown) => {
      const [v, set] = actual.useState(init);
      return [
        v,
        (x: unknown) => {
          setterCalls.count += 1;
          (set as (y: unknown) => void)(x);
        },
      ];
    },
  };
});

import { FpCheckerProvider, useFpChecker } from '../src/index';

const wrapper = ({ children }: { children: ReactNode }) => (
  <FpCheckerProvider publishableKey="pk_test">{children}</FpCheckerProvider>
);
const ok = (eventId: string) => ({ eventId, fromCache: false });

beforeEach(() => {
  identifyMock.mockReset();
  loadMock.mockReset();
  loadMock.mockResolvedValue({ identify: identifyMock });
});
afterEach(cleanup);

describe('FpCheckerProvider', () => {
  it('provider renders on server without loading agent', () => {
    function Child() {
      const { isLoading } = useFpChecker();
      return <span>{String(isLoading)}</span>;
    }
    const html = renderToString(
      <FpCheckerProvider publishableKey="pk_test">
        <Child />
      </FpCheckerProvider>,
    );
    expect(html).toContain('false');
    expect(loadMock).not.toHaveBeenCalled();
  });

  it('loads on the client after mount with the given options', async () => {
    render(
      <FpCheckerProvider publishableKey="pk_test" endpoint="https://e" scriptUrl="/a.js">
        <i />
      </FpCheckerProvider>,
    );
    await waitFor(() => expect(loadMock).toHaveBeenCalledTimes(1));
    expect(loadMock).toHaveBeenCalledWith({ publishableKey: 'pk_test', endpoint: 'https://e', scriptUrl: '/a.js' });
  });

  it('identify updates data/isLoading', async () => {
    let resolve!: (v: unknown) => void;
    identifyMock.mockReturnValue(new Promise((r) => (resolve = r)));
    const { result } = renderHook(() => useFpChecker(), { wrapper });
    let p!: Promise<unknown>;
    act(() => {
      p = result.current.identify({ intentToken: 't', cache: false });
    });
    await waitFor(() => expect(result.current.isLoading).toBe(true));
    await act(async () => {
      resolve(ok('e1'));
      await p;
    });
    expect(result.current.isLoading).toBe(false);
    expect(result.current.data).toEqual(ok('e1'));
    expect(result.current.error).toBeUndefined();
    expect(identifyMock).toHaveBeenCalledWith({ intentToken: 't', cache: false });
  });

  it('identify failure sets error and rethrows', async () => {
    identifyMock.mockRejectedValue(new Error('boom'));
    const { result } = renderHook(() => useFpChecker(), { wrapper });
    let caught: unknown;
    await act(async () => {
      await result.current.identify({ intentToken: 't' }).catch((e) => (caught = e));
    });
    expect((caught as Error).message).toBe('boom');
    expect(result.current.error?.message).toBe('boom');
    expect(result.current.isLoading).toBe(false);
  });

  it('load failure surfaces as error without unhandled rejection', async () => {
    loadMock.mockRejectedValue(new Error('load down'));
    const { result } = renderHook(() => useFpChecker(), { wrapper });
    await waitFor(() => expect(result.current.error?.message).toBe('load down'));
  });

  it('last-started identify wins', async () => {
    const resolvers: Array<(v: unknown) => void> = [];
    identifyMock.mockImplementation(() => new Promise((r) => resolvers.push(r)));
    const { result } = renderHook(() => useFpChecker(), { wrapper });
    let p1!: Promise<unknown>, p2!: Promise<unknown>;
    act(() => {
      p1 = result.current.identify({ intentToken: 'a' });
    });
    await waitFor(() => expect(resolvers.length).toBe(1));
    act(() => {
      p2 = result.current.identify({ intentToken: 'b' });
    });
    await waitFor(() => expect(resolvers.length).toBe(2));
    await act(async () => {
      resolvers[1]!(ok('second'));
      await p2;
    });
    await act(async () => {
      resolvers[0]!(ok('first'));
      expect(await p1).toEqual(ok('first'));
    });
    expect(result.current.data).toEqual(ok('second'));
    expect(result.current.isLoading).toBe(false);
  });

  it('no state updates after unmount', async () => {
    let resolve!: (v: unknown) => void;
    identifyMock.mockReturnValue(new Promise((r) => (resolve = r)));
    const { result, unmount } = renderHook(() => useFpChecker(), { wrapper });
    let p!: Promise<unknown>;
    act(() => {
      p = result.current.identify({ intentToken: 't' });
    });
    unmount();
    const before = setterCalls.count;
    resolve(ok('late'));
    await expect(p).resolves.toEqual(ok('late'));
    expect(setterCalls.count).toBe(before);
  });

  it('no state updates after unmount when identify fails', async () => {
    let reject!: (e: Error) => void;
    identifyMock.mockReturnValue(new Promise((_, r) => (reject = r)));
    const { result, unmount } = renderHook(() => useFpChecker(), { wrapper });
    let p!: Promise<unknown>;
    act(() => {
      p = result.current.identify({ intentToken: 't' }).catch((e) => e);
    });
    unmount();
    const before = setterCalls.count;
    reject(new Error('x'));
    await p;
    expect(setterCalls.count).toBe(before);
  });

  it('older identify finishing first does not set data', async () => {
    const resolvers: Array<(v: unknown) => void> = [];
    identifyMock.mockImplementation(() => new Promise((r) => resolvers.push(r)));
    const { result } = renderHook(() => useFpChecker(), { wrapper });
    let p1!: Promise<unknown>, p2!: Promise<unknown>;
    act(() => {
      p1 = result.current.identify({ intentToken: 'a' });
    });
    await waitFor(() => expect(resolvers.length).toBe(1));
    act(() => {
      p2 = result.current.identify({ intentToken: 'b' });
    });
    await waitFor(() => expect(resolvers.length).toBe(2));
    await act(async () => {
      resolvers[0]!(ok('first'));
      await p1;
    });
    expect(result.current.data).toBeUndefined();
    expect(result.current.isLoading).toBe(true);
    await act(async () => {
      resolvers[1]!(ok('second'));
      await p2;
    });
    expect(result.current.data).toEqual(ok('second'));
    expect(result.current.isLoading).toBe(false);
  });

  it('StrictMode: one load, isLoading settles', async () => {
    identifyMock.mockResolvedValue(ok('s'));
    const { result } = renderHook(() => useFpChecker(), {
      wrapper: ({ children }: { children: ReactNode }) => (
        <StrictMode>
          <FpCheckerProvider publishableKey="pk_test">{children}</FpCheckerProvider>
        </StrictMode>
      ),
    });
    await waitFor(() => expect(loadMock).toHaveBeenCalledTimes(1));
    await act(async () => {
      await result.current.identify({ intentToken: 't' });
    });
    expect(loadMock).toHaveBeenCalledTimes(1);
    expect(result.current.isLoading).toBe(false);
    expect(result.current.data).toEqual(ok('s'));
  });

  it('retries load after a transient load failure', async () => {
    loadMock.mockRejectedValueOnce(new Error('flaky'));
    identifyMock.mockResolvedValue(ok('r'));
    const { result } = renderHook(() => useFpChecker(), { wrapper });
    await waitFor(() => expect(result.current.error?.message).toBe('flaky'));
    await act(async () => {
      await result.current.identify({ intentToken: 't' });
    });
    expect(loadMock).toHaveBeenCalledTimes(2);
    expect(result.current.data).toEqual(ok('r'));
    expect(result.current.error).toBeUndefined();
  });

  describe('mount-time identify from a child effect', () => {
    function Child() {
      const { identify, data } = useFpChecker();
      useEffect(() => {
        identify({ intentToken: 't' }).catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);
      return <span data-testid="d">{data?.eventId ?? 'none'}</span>;
    }
    const tree = (strict: boolean) => {
      const inner = (
        <FpCheckerProvider publishableKey="pk_test">
          <Child />
        </FpCheckerProvider>
      );
      return strict ? <StrictMode>{inner}</StrictMode> : inner;
    };

    it.each([false, true])('result lands in data (StrictMode=%s)', async (strict) => {
      identifyMock.mockResolvedValue(ok('mount'));
      const { getByTestId } = render(tree(strict));
      await waitFor(() => expect(getByTestId('d').textContent).toBe('mount'));
    });
  });

  describe('option change', () => {
    function setup() {
      let latest!: ReturnType<typeof useFpChecker>;
      function Probe() {
        latest = useFpChecker();
        return null;
      }
      const tree = (k: string) => (
        <FpCheckerProvider publishableKey={k}>
          <Probe />
        </FpCheckerProvider>
      );
      const r = render(tree('pk_a'));
      return { get: () => latest, rerender: (k: string) => r.rerender(tree(k)) };
    }

    it('resets data/error/isLoading when the key changes', async () => {
      identifyMock.mockResolvedValue(ok('a'));
      const t = setup();
      await act(async () => {
        await t.get().identify({ intentToken: 't' });
      });
      expect(t.get().data).toEqual(ok('a'));
      identifyMock.mockReturnValue(new Promise(() => {}));
      act(() => {
        void t.get().identify({ intentToken: 't' });
      });
      await waitFor(() => expect(t.get().isLoading).toBe(true));
      act(() => t.rerender('pk_b'));
      expect(t.get().data).toBeUndefined();
      expect(t.get().error).toBeUndefined();
      expect(t.get().isLoading).toBe(false);
      await waitFor(() => expect(loadMock).toHaveBeenLastCalledWith({ publishableKey: 'pk_b' }));
    });

    it('ignores results from the old key', async () => {
      let resolve!: (v: unknown) => void;
      identifyMock.mockReturnValue(new Promise((r) => (resolve = r)));
      const t = setup();
      let p!: Promise<unknown>;
      act(() => {
        p = t.get().identify({ intentToken: 't' });
      });
      await waitFor(() => expect(identifyMock).toHaveBeenCalled());
      act(() => t.rerender('pk_b'));
      await act(async () => {
        resolve(ok('old'));
        await p;
      });
      expect(t.get().data).toBeUndefined();
      expect(t.get().isLoading).toBe(false);
    });

    it('ignores load failure from the old key', async () => {
      let rejectA!: (e: Error) => void;
      loadMock.mockImplementation((o: { publishableKey: string }) =>
        o.publishableKey === 'pk_a'
          ? new Promise((_, r) => (rejectA = r))
          : Promise.resolve({ identify: identifyMock }),
      );
      const t = setup();
      await waitFor(() => expect(loadMock).toHaveBeenCalledTimes(1));
      act(() => t.rerender('pk_b'));
      await waitFor(() => expect(loadMock).toHaveBeenCalledTimes(2));
      await act(async () => {
        rejectA(new Error('old failed'));
        await Promise.resolve();
      });
      expect(t.get().error).toBeUndefined();
    });
  });

  it('useFpChecker outside provider throws a clear error', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => renderHook(() => useFpChecker())).toThrow(/FpCheckerProvider/);
    spy.mockRestore();
  });
});
