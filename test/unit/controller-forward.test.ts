import { FastifyInstance } from 'fastify';

import { ResourceNames } from '../../src/authzgen/compose';
import { Composition, controllerApi, ControllerState, serially } from '../../src/controller/api';
import { Leader } from '../../src/controller/leader';
import { Provisioner } from '../../src/iam/provisioner';
import { registryTuple } from '../../src/iam/registry';
import { MemoryKeto } from './memory-keto';

const composition: Composition = {
  catalog: [],
  resourceNames: {},
  roles: [],
  separations: [],
  pending: ['role r waits for ledger'],
  renamed: {},
  removed: [],
};

const ketoOf = new Map<FastifyInstance, MemoryKeto>();

const replica = async (leader: () => Leader): Promise<FastifyInstance> => {
  const keto = new MemoryKeto();
  const state: ControllerState = {
    keto,
    provisioner: new Provisioner(keto, { roles: {} }, new Map(), {
      resourceNames: { report: { members: [{ service: 'reports', type: 'reports' }] } },
    } as ResourceNames),
    exclusive: serially(),
    live: () => ({ roles: {} }),
    catalog: () => [],
    composition: () => composition,
    etag: () => '"e7"',
    composed: () => undefined,
    applied: () => true,
    ready: () => true,
    leader,
    revoke: async () => undefined,
  };
  const app = await controllerApi(state);
  ketoOf.set(app, keto);
  return app;
};

const urlOf = (app: FastifyInstance): string => `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;

const call = async (url: string, method: string, path: string, init: { body?: unknown; headers?: Record<string, string> } = {}) => {
  const response = await fetch(`${url}${path}`, {
    method,
    headers: { ...(init.body !== undefined ? { 'content-type': 'application/json' } : {}), ...init.headers },
    ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
  });
  const text = await response.text();
  return { status: response.status, etag: response.headers.get('etag'), body: text === '' ? undefined : JSON.parse(text) };
};

describe('a standby replica of the controller', () => {
  let leading: FastifyInstance;
  let standby: FastifyInstance;
  let leaderUrl: string;
  let standbyUrl: string;
  let at: Leader = { self: false };

  beforeAll(async () => {
    leading = await replica(() => ({ self: true }));
    await leading.listen({ port: 0, host: '127.0.0.1' });
    leaderUrl = urlOf(leading);
    standby = await replica(() => at);
    await standby.listen({ port: 0, host: '127.0.0.1' });
    standbyUrl = urlOf(standby);
  });

  afterAll(async () => {
    await standby.close();
    await leading.close();
  });

  it('answers the composition the leader holds, with its ETag', async () => {
    at = { self: false, address: leaderUrl };
    expect(await call(standbyUrl, 'GET', '/composition')).toEqual({ status: 200, etag: '"e7"', body: composition });
    expect(await call(standbyUrl, 'GET', '/composition', { headers: { 'if-none-match': '"e7"' } })).toMatchObject({
      status: 304,
      etag: '"e7"',
    });
  });

  it('hands a write to the leader and answers exactly what the leader answered', async () => {
    at = { self: false, address: leaderUrl };
    const write = { body: { subject: 'u1', role: 'nobody' } };
    const direct = await call(leaderUrl, 'POST', '/assignments', write);
    expect(direct.status).toBe(422);
    expect(await call(standbyUrl, 'POST', '/assignments', write)).toEqual(direct);
  });

  it('hands the record of a new resource to the leader, which alone writes it', async () => {
    at = { self: false, address: leaderUrl };
    expect(await call(standbyUrl, 'POST', '/resources', { body: { resourceName: 'report', id: 'monthly' } })).toEqual({
      status: 200,
      etag: null,
      body: { resourceName: 'report', id: 'monthly' },
    });
    expect(ketoOf.get(leading)!.tuples).toEqual([registryTuple('report', 'monthly')]);
    expect(ketoOf.get(standby)!.tuples).toEqual([]);
    expect(await call(standbyUrl, 'POST', '/resources', { body: { resourceName: 'nothing', id: 'x' } })).toMatchObject({
      status: 422,
      body: { errors: ['no resource name called nothing'] },
    });
    expect((await call(standbyUrl, 'DELETE', '/resources', { body: { resourceName: 'report', id: 'monthly' } })).body).toEqual({
      orphaned: [],
    });
    expect(ketoOf.get(leading)!.tuples).toEqual([]);
  });

  it('answers what it composed itself, without the leader', async () => {
    at = { self: false };
    expect((await call(standbyUrl, 'GET', '/ready')).status).toBe(200);
    expect((await call(standbyUrl, 'GET', '/derivation.txt')).status).toBe(200);
  });

  it('refuses a write while no replica leads', async () => {
    at = { self: false };
    expect(await call(standbyUrl, 'POST', '/assignments', { body: { subject: 'u1', role: 'r' } })).toMatchObject({
      status: 503,
      body: { errors: ['no controller replica leads yet'] },
    });
  });

  it('never hands on a request another replica handed it', async () => {
    at = { self: false, address: leaderUrl };
    const other = await replica(() => ({ self: false, address: standbyUrl }));
    await other.listen({ port: 0, host: '127.0.0.1' });
    at = { self: false, address: urlOf(other) };
    expect(await call(urlOf(other), 'GET', '/composition')).toMatchObject({
      status: 503,
      body: { errors: ['no controller replica leads yet'] },
    });
    await other.close();
  });

  it('says so when the replica it saw leading does not answer', async () => {
    const gone = await replica(() => ({ self: true }));
    await gone.listen({ port: 0, host: '127.0.0.1' });
    const goneUrl = urlOf(gone);
    await gone.close();
    at = { self: false, address: goneUrl };
    const answer = await call(standbyUrl, 'GET', '/composition');
    expect(answer.status).toBe(503);
    expect(answer.body.errors[0]).toMatch(new RegExp(`^the leading replica at ${goneUrl} does not answer`));
  });
});
