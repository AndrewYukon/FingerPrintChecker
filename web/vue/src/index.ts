import { load } from '@fpchecker/agent';
import type { FpAgent, IdentifyOptions, IdentifyResult, LoadOptions } from '@fpchecker/agent';
import {
  getCurrentInstance,
  inject,
  onMounted,
  readonly,
  shallowRef,
  type App,
  type InjectionKey,
  type Plugin,
  type Ref,
} from 'vue';

export type { IdentifyOptions, IdentifyResult, LoadOptions } from '@fpchecker/agent';

export interface FpCheckerState {
  identify(opts: IdentifyOptions): Promise<IdentifyResult>;
  data: Readonly<Ref<IdentifyResult | undefined>>;
  error: Readonly<Ref<Error | undefined>>;
  isLoading: Readonly<Ref<boolean>>;
}

interface Controller {
  state: FpCheckerState;
  ensureLoaded(): void;
  dispose(): void;
}

const key: InjectionKey<Controller> = Symbol('fpchecker');

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

function createController(opts: LoadOptions): Controller {
  const data = shallowRef<IdentifyResult | undefined>(undefined);
  const error = shallowRef<Error | undefined>(undefined);
  const isLoading = shallowRef(false);
  let disposed = false;
  let callId = 0;
  let agentPromise: Promise<FpAgent> | null = null;

  const getAgent = (): Promise<FpAgent> => {
    if (!agentPromise) {
      agentPromise = load({
        publishableKey: opts.publishableKey,
        ...(opts.endpoint !== undefined ? { endpoint: opts.endpoint } : {}),
        ...(opts.scriptUrl !== undefined ? { scriptUrl: opts.scriptUrl } : {}),
      });
    }
    return agentPromise;
  };

  const ensureLoaded = (): void => {
    if (typeof window === 'undefined' || disposed) return;
    getAgent().catch((e: unknown) => {
      if (!disposed) error.value = toError(e);
    });
  };

  const identify = async (o: IdentifyOptions): Promise<IdentifyResult> => {
    const id = ++callId;
    const isLatest = () => !disposed && callId === id;
    isLoading.value = true;
    try {
      const agent = await getAgent();
      const result = await agent.identify(o);
      if (isLatest()) {
        data.value = result;
        error.value = undefined;
      }
      return result;
    } catch (e) {
      if (isLatest()) error.value = toError(e);
      throw e;
    } finally {
      if (isLatest()) isLoading.value = false;
    }
  };

  return {
    state: { identify, data: readonly(data), error: readonly(error), isLoading: readonly(isLoading) },
    ensureLoaded,
    dispose: () => {
      disposed = true;
    },
  };
}

export const fpChecker: Plugin<[LoadOptions]> = {
  install(app: App, opts: LoadOptions) {
    const controller = createController(opts);
    app.provide(key, controller);
    const unmount = app.unmount.bind(app);
    app.unmount = () => {
      controller.dispose();
      unmount();
    };
  },
};

export function useFpChecker(): FpCheckerState {
  const controller = inject(key, null);
  if (!controller) {
    throw new Error('useFpChecker requires the plugin: app.use(fpChecker, { publishableKey }).');
  }
  if (getCurrentInstance()) onMounted(() => controller.ensureLoaded());
  return controller.state;
}
