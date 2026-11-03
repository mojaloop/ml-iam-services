import { afterEach, describe, expect, it, vi } from 'vitest';

const cluster = vi.hoisted(() => ({
  onChange: undefined as undefined | (() => Promise<void>),
  onRollout: undefined as undefined | (() => Promise<void>),
  lists: 0,
  release: [] as Array<() => void>,
  names: [] as unknown[],
  routes: [] as unknown[],
  documents: [] as unknown[],
}));

vi.mock('../../src/operator/cluster', async (original) => ({
  ...(await original<typeof import('../../src/operator/cluster')>()),
  listRoutes: vi.fn(async () => {
    cluster.lists += 1;
    if (cluster.lists > 1) await new Promise<void>((resolve) => cluster.release.push(resolve));
    return cluster.routes;
  }),
  listDocuments: vi.fn(async () => cluster.documents),
  listGateways: vi.fn(async () => []),
  listResourceNames: vi.fn(async () => cluster.names),
  publish: vi.fn(async () => undefined),
  setStatus: vi.fn(async () => undefined),
  reportOnRoute: vi.fn(async () => undefined),
  watchInputs: vi.fn(async (onChange: () => Promise<void>) => {
    cluster.onChange = onChange;
    return { close: () => undefined };
  }),
  watchBackends: vi.fn(async (_reads: unknown, onChange: () => Promise<void>) => {
    cluster.onRollout = onChange;
    return { close: () => undefined };
  }),
}));

import { setStatus } from '../../src/operator/cluster';
import { Operator } from '../../src/operator/server';

describe('Operator', () => {
  afterEach(() => vi.restoreAllMocks());

  it('composes a listing handed over one object at a time in two passes', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const operator = new Operator({ namespace: 'ory' });
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

  it('composes again when a backend it reads rolls out, with nothing else moving', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    cluster.lists = 0;
    const operator = new Operator({ namespace: 'ory' });
    await operator.start();

    await cluster.onRollout!();
    while (cluster.release.length > 0) {
      cluster.release.shift()!();
      await new Promise((resolve) => setImmediate(resolve));
    }
    operator.stop();

    expect(cluster.lists).toBe(2);
  });

  const sourced = {
    metadata: { name: 'participant', namespace: 'ory', generation: 1 },
    spec: { members: [{ service: 'ledger', type: 'participants' }], source: { url: 'http://ledger.test/participants', id: '/name' } },
  };
  const readyOf = () => {
    const call = vi.mocked(setStatus).mock.calls.find(([, , name]) => name === 'participant');
    return (call?.[3] as { conditions: Array<{ reason: string; message: string }> } | undefined)?.conditions[0];
  };

  it('refuses a resource name whose source answers in a shape it does not declare, when the object changes', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    vi.mocked(setStatus).mockClear();
    cluster.lists = 0;
    cluster.names = [sourced];
    const reason = 'participant: http://ledger.test/participants answered no array at pointer ""';
    const operator = new Operator({
      namespace: 'ory',
      leading: () => true,
      count: async () => ({ resources: 0, failed: reason, misdeclared: true }),
    });
    await operator.run();
    expect(readyOf()).toMatchObject({ reason: 'Refused', message: reason });
  });

  it('keeps a resource name whose source is unreachable, and says so', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    vi.mocked(setStatus).mockClear();
    cluster.lists = 0;
    cluster.names = [sourced];
    const operator = new Operator({
      namespace: 'ory',
      leading: () => true,
      count: async () => ({ resources: 3, read: '2026-11-01T00:00:00.000Z', failed: 'connect ECONNREFUSED' }),
    });
    await operator.run();
    expect(readyOf()?.reason).not.toBe('Refused');
    expect(readyOf()?.message).toMatch(/its source did not answer: connect ECONNREFUSED/);
  });

  it('refuses an AuthzDocument that does not compose, saying why', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    vi.mocked(setStatus).mockClear();
    cluster.lists = 0;
    cluster.names = [];
    cluster.routes = [
      {
        metadata: {
          name: 'reports',
          namespace: 'acme',
          annotations: { 'iam.mojaloop.io/reports-api.service': 'reports', 'iam.mojaloop.io/reports-api.schema': 'reports' },
        },
        spec: {
          hostnames: ['reports.test'],
          rules: [
            {
              matches: [{ path: { type: 'PathPrefix', value: '/' } }],
              filters: [{ type: 'ExternalAuth' }],
              backendRefs: [{ name: 'reports-api', port: 3000 }],
            },
          ],
        },
      },
    ];
    cluster.documents = [
      {
        metadata: { name: 'reports', namespace: 'acme', generation: 1 },
        spec: {
          document: {
            openapi: '3.1.0',
            info: { title: 'reports', version: '1' },
            paths: { '/x': { get: { operationId: 'x', responses: { 200: { description: 'ok' } } } } },
          },
        },
      },
    ];
    try {
      await new Operator({ namespace: 'ory', leading: () => true }).run();
      const call = vi.mocked(setStatus).mock.calls.find(([, namespace, name]) => namespace === 'acme' && name === 'reports');
      const ready = (call?.[3] as { conditions: Array<{ reason: string; message: string }> } | undefined)?.conditions[0];
      expect(ready?.reason).toBe('Refused');
      expect(ready?.message).toMatch(/GET \/x: summary is required for the catalog/);
    } finally {
      cluster.routes = [];
      cluster.documents = [];
    }
  });
});
