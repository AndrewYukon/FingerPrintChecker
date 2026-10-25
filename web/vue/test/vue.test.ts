import { mount, flushPromises } from '@vue/test-utils';
import { createApp, createSSRApp, defineComponent, h, isReadonly } from 'vue';
import { renderToString } from 'vue/server-renderer';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const identifyMock = vi.fn();
const loadMock = vi.fn();
vi.mock('@fpchecker/agent', async (orig) => ({
  ...(await orig<typeof import('@fpchecker/agent')>()),
  load: (o: unknown) => loadMock(o),
}));

import { fpChecker, useFpChecker } from '../src/index';

const ok = (eventId: string) => ({ eventId, fromCache: false });
const plugin = [fpChecker, { publishableKey: 'pk_test' }] as const;

function mountHook() {
  let api!: ReturnType<typeof useFpChecker>;
  const C = defineComponent({
    setup() {
      api = useFpChecker();
      return () => h('div');
    },
  });
  const w = mount(C, { global: { plugins: [[...plugin]] } });
  return { api, w };
}

beforeEach(() => {
  identifyMock.mockReset();
  loadMock.mockReset();
  loadMock.mockResolvedValue({ identify: identifyMock });
});

describe('fpChecker plugin', () => {
  it('plugin renders on server without loading agent', async () => {
    const C = defineComponent({
      setup() {
        const { isLoading } = useFpChecker();
        return () => h('span', String(isLoading.value));
      },
    });
    const app = createSSRApp(C);
    app.use(fpChecker, { publishableKey: 'pk_test' });
    expect(await renderToString(app)).toContain('false');
    expect(loadMock).not.toHaveBeenCalled();
  });

  it('loads on mount with the given options', async () => {
    mountHook();
    await flushPromises();
    expect(loadMock).toHaveBeenCalledTimes(1);
    expect(loadMock).toHaveBeenCalledWith({ publishableKey: 'pk_test' });
  });

  it('identify updates data/isLoading', async () => {
    let resolve!: (v: unknown) => void;
    identifyMock.mockReturnValue(new Promise((r) => (resolve = r)));
    const { api } = mountHook();
    const p = api.identify({ intentToken: 't', cache: false });
    await flushPromises();
    expect(api.isLoading.value).toBe(true);
    resolve(ok('e1'));
    await p;
    expect(api.isLoading.value).toBe(false);
    expect(api.data.value).toEqual(ok('e1'));
    expect(api.error.value).toBeUndefined();
    expect(identifyMock).toHaveBeenCalledWith({ intentToken: 't', cache: false });
  });

  it('identify failure sets error and rethrows', async () => {
    identifyMock.mockRejectedValue(new Error('boom'));
    const { api } = mountHook();
    await expect(api.identify({ intentToken: 't' })).rejects.toThrow('boom');
    expect(api.error.value?.message).toBe('boom');
    expect(api.isLoading.value).toBe(false);
  });

  it('load failure surfaces as error without unhandled rejection', async () => {
    loadMock.mockRejectedValue(new Error('load down'));
    const { api } = mountHook();
    await flushPromises();
    expect(api.error.value?.message).toBe('load down');
  });

  it('last-started identify wins', async () => {
    const resolvers: Array<(v: unknown) => void> = [];
    identifyMock.mockImplementation(() => new Promise((r) => resolvers.push(r)));
    const { api } = mountHook();
    const p1 = api.identify({ intentToken: 'a' });
    await flushPromises();
    const p2 = api.identify({ intentToken: 'b' });
    await flushPromises();
    resolvers[1]!(ok('second'));
    await p2;
    resolvers[0]!(ok('first'));
    expect(await p1).toEqual(ok('first'));
    expect(api.data.value).toEqual(ok('second'));
    expect(api.isLoading.value).toBe(false);
  });

  it('no state updates after unmount', async () => {
    let resolve!: (v: unknown) => void;
    identifyMock.mockReturnValue(new Promise((r) => (resolve = r)));
    const { api, w } = mountHook();
    const p = api.identify({ intentToken: 't' });
    await flushPromises();
    w.unmount();
    // app.unmount via test-utils disposes the controller
    resolve(ok('late'));
    await expect(p).resolves.toEqual(ok('late'));
    expect(api.data.value).toBeUndefined();
  });

  it('useFpChecker without the plugin throws a clear error', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const C = defineComponent({
      setup() {
        useFpChecker();
        return () => h('div');
      },
    });
    expect(() => mount(C)).toThrow(/fpChecker/);
    warn.mockRestore();
  });

  it('retries load after a transient load failure', async () => {
    loadMock.mockRejectedValueOnce(new Error('flaky'));
    identifyMock.mockResolvedValue(ok('r'));
    const { api } = mountHook();
    await flushPromises();
    expect(api.error.value?.message).toBe('flaky');
    await api.identify({ intentToken: 't' });
    expect(loadMock).toHaveBeenCalledTimes(2);
    expect(api.data.value).toEqual(ok('r'));
    expect(api.error.value).toBeUndefined();
  });

  it('older identify finishing first does not set data', async () => {
    const resolvers: Array<(v: unknown) => void> = [];
    identifyMock.mockImplementation(() => new Promise((r) => resolvers.push(r)));
    const { api } = mountHook();
    const p1 = api.identify({ intentToken: 'a' });
    await flushPromises();
    const p2 = api.identify({ intentToken: 'b' });
    await flushPromises();
    resolvers[0]!(ok('first'));
    await p1;
    expect(api.data.value).toBeUndefined();
    expect(api.isLoading.value).toBe(true);
    resolvers[1]!(ok('second'));
    await p2;
    expect(api.data.value).toEqual(ok('second'));
    expect(api.isLoading.value).toBe(false);
  });

  it('exposes shallow readonly refs: result object stays plain', async () => {
    identifyMock.mockResolvedValue(ok('x'));
    const { api } = mountHook();
    await api.identify({ intentToken: 't' });
    expect(isReadonly(api.data)).toBe(true);
    expect(isReadonly(api.data.value)).toBe(false);
  });

  it('a call started after unmount works (state is re-armed)', async () => {
    identifyMock.mockResolvedValue(ok('x'));
    let api!: ReturnType<typeof useFpChecker>;
    const C = defineComponent({
      setup() {
        api = useFpChecker();
        return () => h('div');
      },
    });
    const app = createApp(C);
    app.use(fpChecker, { publishableKey: 'pk_test' });
    app.mount(document.createElement('div'));
    app.unmount();
    await api.identify({ intentToken: 't' });
    expect(api.data.value).toEqual(ok('x'));
  });

  it('fallback: wraps app.unmount when app.onUnmount is unavailable', async () => {
    identifyMock.mockResolvedValue(ok('x'));
    let controllerState!: ReturnType<typeof useFpChecker>;
    const fakeApp = {
      provide: (_k: unknown, v: { state: typeof controllerState }) => (controllerState = v.state),
      unmount: vi.fn(),
    };
    fpChecker.install!(fakeApp as never, { publishableKey: 'pk_test' });
    let resolve!: (v: unknown) => void;
    identifyMock.mockReturnValue(new Promise((r) => (resolve = r)));
    const p = controllerState.identify({ intentToken: 't' });
    await flushPromises();
    fakeApp.unmount();
    resolve(ok('late'));
    await p;
    expect(controllerState.data.value).toBeUndefined();
  });
});
