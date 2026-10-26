// @vitest-environment node
import { renderToString } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

const loadMock = vi.fn();
vi.mock('@fingerprintchecker/agent', async (orig) => ({
  ...(await orig<typeof import('@fingerprintchecker/agent')>()),
  load: (o: unknown) => loadMock(o),
}));

import { FpCheckerProvider, useFpChecker } from '../src/index';

describe('identify on the server', () => {
  it('rejects with code ssr and does not call load', async () => {
    let api!: ReturnType<typeof useFpChecker>;
    function Child() {
      api = useFpChecker();
      return null;
    }
    renderToString(
      <FpCheckerProvider publishableKey="pk_test">
        <Child />
      </FpCheckerProvider>,
    );
    await expect(api.identify({ intentToken: 't' })).rejects.toMatchObject({ code: 'ssr' });
    expect(loadMock).not.toHaveBeenCalled();
  });
});
