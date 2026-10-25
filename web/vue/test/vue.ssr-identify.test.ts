// @vitest-environment node
import { createSSRApp, defineComponent, h } from 'vue';
import { renderToString } from 'vue/server-renderer';
import { describe, expect, it, vi } from 'vitest';

const loadMock = vi.fn();
vi.mock('@fpchecker/agent', async (orig) => ({
  ...(await orig<typeof import('@fpchecker/agent')>()),
  load: (o: unknown) => loadMock(o),
}));

import { fpChecker, useFpChecker } from '../src/index';

describe('identify on the server', () => {
  it('rejects with code ssr and does not call load', async () => {
    let api!: ReturnType<typeof useFpChecker>;
    const C = defineComponent({
      setup() {
        api = useFpChecker();
        return () => h('div');
      },
    });
    const app = createSSRApp(C);
    app.use(fpChecker, { publishableKey: 'pk_test' });
    await renderToString(app);
    await expect(api.identify({ intentToken: 't' })).rejects.toMatchObject({ code: 'ssr' });
    expect(loadMock).not.toHaveBeenCalled();
  });
});
