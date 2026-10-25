import { act, cleanup, render, renderHook, waitFor } from '@testing-library/react';
import { renderToString } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

const identifyMock = vi.fn();
const loadMock = vi.fn();
vi.mock('@fpchecker/agent', () => ({ load: (o: unknown) => loadMock(o) }));

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
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    let resolve!: (v: unknown) => void;
    identifyMock.mockReturnValue(new Promise((r) => (resolve = r)));
    const { result, unmount } = renderHook(() => useFpChecker(), { wrapper });
    let p!: Promise<unknown>;
    act(() => {
      p = result.current.identify({ intentToken: 't' });
    });
    unmount();
    resolve(ok('late'));
    await expect(p).resolves.toEqual(ok('late'));
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('useFpChecker outside provider throws a clear error', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => renderHook(() => useFpChecker())).toThrow(/FpCheckerProvider/);
    spy.mockRestore();
  });
});
