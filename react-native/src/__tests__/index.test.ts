const identifyMock = jest.fn();
const rn: { NativeModules: Record<string, unknown>; Platform: { OS: string } } = {
  NativeModules: { FingerPrintCheckerModule: { identify: identifyMock } },
  Platform: { OS: 'ios' },
};
jest.mock('react-native', () => rn, { virtual: true });

import { FingerPrintChecker } from '../index';

const ok = { ok: true, visitorId: 'v1', attestation: 'a1', rawJson: '{}' };

beforeEach(() => {
  identifyMock.mockReset();
  rn.NativeModules.FingerPrintCheckerModule = { identify: identifyMock };
});

const make = () => new FingerPrintChecker({ publishableKey: 'pk_x', baseUrl: undefined, powDifficulty: 3 });

describe('identify', () => {
  it('maps success and defaults lists to empty', async () => {
    identifyMock.mockResolvedValue({ ...ok, trustScore: 0.9 });
    const r = await make().identify('tok', { linkedId: 'L', tags: { a: [1, 'x', null, true, { b: 2 }] } });
    expect(r).toMatchObject({ ok: true, visitorId: 'v1', trustScore: 0.9, trustDeductions: [], shadowDeductions: [], rawJson: '{}' });
    expect(identifyMock).toHaveBeenCalledWith({
      config: { publishableKey: 'pk_x', powDifficulty: 3 },
      intentToken: 'tok',
      linkedId: 'L',
      tags: { a: [1, 'x', null, true, { b: 2 }] },
    });
  });

  it('keeps deduction lists', async () => {
    identifyMock.mockResolvedValue({ ...ok, trustDeductions: ['x'], shadowDeductions: ['y'] });
    const r = await make().identify('tok');
    expect(r).toMatchObject({ trustDeductions: ['x'], shadowDeductions: ['y'] });
  });

  it('passes failure through', async () => {
    identifyMock.mockResolvedValue({ ok: false, reason: 'http_error', httpStatus: 503 });
    expect(await make().identify('tok')).toEqual({ ok: false, reason: 'http_error', httpStatus: 503 });
  });

  class Foo { a = 1; }
  const cyc: Record<string, unknown> = {};
  cyc.self = cyc;
  const bad: Array<[string, unknown]> = [
    ['Date', { d: new Date() }],
    ['class instance', { f: new Foo() }],
    ['NaN', { n: NaN }],
    ['Infinity', { n: Infinity }],
    ['nested undefined', { a: { b: undefined } }],
    ['function', { f: () => 1 }],
    ['Map', { m: new Map() }],
    ['cycle', cyc],
    ['undefined in array', { a: [undefined] }],
  ];
  it.each(bad)('invalid_tags for %s without calling native', async (_n, tags) => {
    const r = await make().identify('tok', { tags: tags as Record<string, unknown> });
    expect(r).toEqual({ ok: false, reason: 'invalid_tags', httpStatus: 0 });
    expect(identifyMock).not.toHaveBeenCalled();
  });

  it('bad_intent_token / bad_config without calling native', async () => {
    expect(await make().identify('')).toEqual({ ok: false, reason: 'bad_intent_token', httpStatus: 0 });
    expect(await new FingerPrintChecker({ publishableKey: '' }).identify('tok')).toEqual({ ok: false, reason: 'bad_config', httpStatus: 0 });
    expect(identifyMock).not.toHaveBeenCalled();
  });

  it('not_linked when module missing', async () => {
    delete rn.NativeModules.FingerPrintCheckerModule;
    expect(await make().identify('tok')).toEqual({ ok: false, reason: 'not_linked', httpStatus: 0 });
  });

  it('bridge_error on rejection, throw, and malformed reply', async () => {
    identifyMock.mockRejectedValueOnce(new Error('boom'));
    expect(await make().identify('tok')).toEqual({ ok: false, reason: 'bridge_error', httpStatus: 0 });
    identifyMock.mockImplementationOnce(() => { throw new Error('sync'); });
    expect(await make().identify('tok')).toEqual({ ok: false, reason: 'bridge_error', httpStatus: 0 });
    identifyMock.mockResolvedValueOnce({ foo: 1 });
    expect(await make().identify('tok')).toEqual({ ok: false, reason: 'bridge_error', httpStatus: 0 });
    identifyMock.mockResolvedValueOnce(null);
    expect(await make().identify('tok')).toEqual({ ok: false, reason: 'bridge_error', httpStatus: 0 });
    identifyMock.mockResolvedValueOnce({ ok: true, visitorId: 1, attestation: 'a' });
    expect(await make().identify('tok')).toEqual({ ok: false, reason: 'bridge_error', httpStatus: 0 });
    identifyMock.mockResolvedValueOnce({ ok: true, visitorId: 'v', attestation: '' });
    expect(await make().identify('tok')).toEqual({ ok: false, reason: 'bridge_error', httpStatus: 0 });
    identifyMock.mockResolvedValueOnce({ ok: true, visitorId: 'v' });
    expect(await make().identify('tok')).toEqual({ ok: false, reason: 'bridge_error', httpStatus: 0 });
  });

  it('accepts a missing or null visitorId', async () => {
    identifyMock.mockResolvedValueOnce({ ok: true, attestation: 'a1', rawJson: '{}' });
    const r1 = await make().identify('tok');
    expect(r1).toMatchObject({ ok: true, attestation: 'a1' });
    expect((r1 as { visitorId?: string }).visitorId).toBeUndefined();
    identifyMock.mockResolvedValueOnce({ ok: true, visitorId: null, attestation: 'a1' });
    const r2 = await make().identify('tok');
    expect(r2).toMatchObject({ ok: true, attestation: 'a1' });
    expect((r2 as { visitorId?: string }).visitorId).toBeUndefined();
  });
});
