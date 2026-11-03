import { ResourceNames } from '../../src/authzgen/compose';
import { CatalogPermission } from '../../src/authzgen/types';
import { Provisioner } from '../../src/iam/provisioner';
import { registryTuple } from '../../src/iam/registry';
import { MemoryKeto } from './memory-keto';

const names: ResourceNames = {
  resourceNames: {
    participant: {
      members: [{ service: 'ledger', type: 'participants' }],
      source: { url: 'http://ledger.test/participants', id: '/name' },
    },
    report: { members: [{ service: 'reports', type: 'reports' }] },
  },
} as ResourceNames;

/** A source answering whatever `answer` says now, counting each read it gets. */
const source = () => {
  const state = { reads: 0, answer: (): Promise<Response> => Promise.resolve(Response.json([{ name: 'dfsp-a' }])) };
  const fetchImpl = (() => {
    state.reads += 1;
    return state.answer();
  }) as unknown as typeof fetch;
  return { state, fetchImpl };
};

const setup = () => {
  const keto = new MemoryKeto();
  const { state, fetchImpl } = source();
  const provisioner = new Provisioner(keto, { roles: {} }, new Map(), names, fetchImpl);
  return { keto, state, provisioner };
};

describe('a resource name read from its declared source, when asked', () => {
  it('lists what the source lists now, beside what services recorded', async () => {
    const { keto, provisioner } = setup();
    keto.tuples.push(registryTuple('participant', 'dfsp-b'), registryTuple('report', 'monthly'));
    expect(await provisioner.listed('participant')).toEqual({
      resources: [
        { resourceName: 'participant', id: 'dfsp-a' },
        { resourceName: 'participant', id: 'dfsp-b' },
      ],
      stale: {},
      read: { participant: expect.any(String) },
    });
  });

  it('shows an id the moment the source lists it, with no read between requests', async () => {
    const { state, provisioner } = setup();
    expect((await provisioner.resources('participant')).map((r) => r.id)).toEqual(['dfsp-a']);
    state.answer = () => Promise.resolve(Response.json([{ name: 'dfsp-a' }, { name: 'dfsp-new' }]));
    expect((await provisioner.resources('participant')).map((r) => r.id)).toEqual(['dfsp-a', 'dfsp-new']);
    expect(state.reads).toBe(2);
  });

  it('never reads a source for a resource name that declares none', async () => {
    const { keto, state, provisioner } = setup();
    keto.tuples.push(registryTuple('report', 'monthly'));
    expect(await provisioner.listed('report')).toEqual({ resources: [{ resourceName: 'report', id: 'monthly' }], stale: {}, read: {} });
    expect(state.reads).toBe(0);
  });

  it('shares one read among the readers that arrive while it is under way', async () => {
    const { state, provisioner } = setup();
    let release!: (response: Response) => void;
    state.answer = () => new Promise((resolve) => (release = resolve));
    const both = Promise.all([provisioner.resources('participant'), provisioner.resources('participant')]);
    release(Response.json([{ name: 'dfsp-a' }]));
    expect((await both).map((listed) => listed.map((r) => r.id))).toEqual([['dfsp-a'], ['dfsp-a']]);
    expect(state.reads).toBe(1);
  });

  it('answers a source that fails with its last good read, naming it stale with the reason', async () => {
    const { state, provisioner } = setup();
    await provisioner.resources('participant');
    state.answer = () => Promise.reject(new Error('connect ECONNREFUSED'));
    const { resources, stale } = await provisioner.listed('participant');
    expect(resources.map((r) => r.id)).toEqual(['dfsp-a']);
    expect(stale['participant']).toMatchObject({ reason: 'connect ECONNREFUSED', since: expect.any(String) });
  });

  it('names a source stale with no last read, and one answering the wrong shape', async () => {
    const { state, provisioner } = setup();
    state.answer = () => Promise.resolve(Response.json({ rows: [] }));
    expect(await provisioner.listed('participant')).toEqual({
      resources: [],
      stale: { participant: { reason: 'participant: http://ledger.test/participants answered no array at pointer ""', misdeclared: true } },
      read: {},
    });
  });

  it('tells whoever follows the figures what each name lists, and again after a resource is recorded', async () => {
    const { provisioner } = setup();
    const told: Array<Record<string, unknown>> = [];
    provisioner.onListed = (figures) => told.push(figures);
    await provisioner.listed('participant');
    expect(told).toEqual([{ participant: { resources: 1, read: expect.any(String) } }]);

    await provisioner.provision({ resourceName: 'participant', id: 'dfsp-b' });
    await vi.waitFor(() => expect(told).toHaveLength(2));
    expect(told[1]).toEqual({ participant: { resources: 2, read: expect.any(String) } });
  });

  it('counts a misdeclared source as refused and an unreachable one as failed', async () => {
    const { state, provisioner } = setup();
    state.answer = () => Promise.resolve(Response.json({ rows: [] }));
    expect(await provisioner.count('participant')).toMatchObject({ resources: 0, misdeclared: true });
    state.answer = () => Promise.reject(new Error('connect ECONNREFUSED'));
    const unreachable = await provisioner.count('participant');
    expect(unreachable).toEqual({ resources: 0, failed: 'connect ECONNREFUSED' });
  });

  it('leaves out an id the IAM could not tell from its own words', async () => {
    const { state, provisioner } = setup();
    state.answer = () => Promise.resolve(Response.json([{ name: 'dfsp-a' }, { name: '$all' }, { name: 'a,b' }]));
    expect((await provisioner.resources('participant')).map((r) => r.id)).toEqual(['dfsp-a']);
  });

  it('checks an assignment against what the source lists now, and says why when it cannot', async () => {
    const getParticipant: CatalogPermission = {
      id: 'ledger.getParticipant',
      relation: 'getParticipant',
      operationId: 'getParticipant',
      summary: 'Reads a participant',
      deprecated: false,
      method: 'GET',
      path: '/participants/{name}',
      scopedBy: ['participants'],
      bound: ['participants'],
      resourceNames: { participants: 'participant' },
    };
    const keto = new MemoryKeto();
    const { state, fetchImpl } = source();
    const roles = { roles: { operator: { grants: [{ permission: 'ledger.getParticipant' }] } } };
    const provisioner = new Provisioner(keto, roles, new Map([[getParticipant.id, getParticipant]]), names, fetchImpl);

    expect(await provisioner.problemsWith('u1', { role: 'operator', resources: { participant: 'dfsp-a' } })).toEqual([]);
    state.answer = () => Promise.resolve(new Response('', { status: 503 }));
    expect(await provisioner.problemsWith('u1', { role: 'operator', resources: { participant: 'dfsp-new' } })).toEqual([
      expect.stringMatching(/^no participant called dfsp-new as of .+: its source did not answer \(participant: http:\/\/ledger.test\/participants answered 503\)$/),
    ]);
  });
});
