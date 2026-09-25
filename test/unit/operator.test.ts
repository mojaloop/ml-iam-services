import { afterEach, describe, expect, it, vi } from 'vitest';

const cluster = vi.hoisted(() => ({
  onChange: undefined as undefined | (() => Promise<void>),
  lists: 0,
  release: [] as Array<() => void>,
}));

vi.mock('../../src/operator/cluster', () => ({
  listRoutes: vi.fn(async () => {
    cluster.lists += 1;
    if (cluster.lists > 1) await new Promise<void>((resolve) => cluster.release.push(resolve));
    return [];
  }),
  listDocuments: vi.fn(async () => []),
  listGateways: vi.fn(async () => []),
  publish: vi.fn(async () => undefined),
  reportOn: vi.fn(async () => undefined),
  reportOnRoute: vi.fn(async () => undefined),
  watchInputs: vi.fn(async (onChange: () => Promise<void>) => {
    cluster.onChange = onChange;
    return { close: () => undefined };
  }),
}));

import { Operator } from '../../src/operator/server';

describe('Operator', () => {
  afterEach(() => vi.restoreAllMocks());

  it('composes a listing handed over one object at a time in two passes', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const operator = new Operator({ namespace: 'ory', refreshMs: 3_600_000 });
    await operator.start();
    expect(cluster.lists).toBe(1);

    const listing = (async () => {
      for (let i = 0; i < 40; i++) await cluster.onChange!();
    })();
    await listing;
    while (cluster.release.length > 0) {
      cluster.release.shift()!();
      await new Promise((resolve) => setImmediate(resolve));
    }
    operator.stop();

    expect(cluster.lists).toBe(3);
  });
});
