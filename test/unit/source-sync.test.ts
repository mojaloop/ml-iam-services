import { ResourceNames } from '../../src/authzgen/compose';
import { Tuple } from '../../src/iam/materialize';
import { idsFrom, SourceShapeError, startSourceSync, syncTarget, targetsOf } from '../../src/iam/source-sync';

const names: ResourceNames = {
  resourceNames: {
    Participant: {
      members: [
        { service: 'mcm', type: 'dfsps' },
        { service: 'ledger', type: 'participants' },
      ],
      source: { url: 'http://central-ledger:3001/participants', id: '/name' },
    },
  },
};

class FakeRegistry {
  tuples: Tuple[] = [];
  async query(params: Record<string, string>): Promise<Tuple[]> {
    return this.tuples.filter((t) => params['subject_id'] === undefined || t.subject_id === params['subject_id']);
  }
  async putAll(added: Tuple[]): Promise<void> {
    this.tuples.push(...added);
  }
  async deleteWhere(params: Record<string, string>): Promise<void> {
    this.tuples = this.tuples.filter((t) => !(t.object === params['object'] && t.subject_id === params['subject_id']));
  }
}

const row = (object: string, subject: string): Tuple => ({
  namespace: 'Resource',
  object,
  relation: 'exists',
  subject_id: subject,
});

const answering = (body: unknown, status = 200): typeof fetch =>
  (async () => ({ ok: status < 400, status, json: async () => body })) as unknown as typeof fetch;

describe('resolving a declared source', () => {
  it('targets the resource name itself, whatever its members spell', () => {
    expect(targetsOf(names)).toEqual([
      {
        resourceName: 'Participant',
        source: names.resourceNames!['Participant']!.source,
      },
    ]);
  });

  it('skips a resource name with no source', () => {
    expect(targetsOf({ resourceNames: { Report: { members: [{ service: 'reports', type: 'reports' }] } } })).toEqual(
      [],
    );
  });
});

describe('reading ids by the declared pointers', () => {
  const target = targetsOf(names)[0]!;

  it('reads a bare array of objects, the body being the array when list is omitted', () => {
    expect(idsFrom([{ name: 'dfsp1' }, { name: 'dfsp2' }], target)).toEqual(['dfsp1', 'dfsp2']);
  });

  it('reaches into a wrapped response', () => {
    const wrapped = targetsOf({
      resourceNames: {
        Participant: {
          members: [{ service: 'ledger', type: 'participants' }],
          source: { url: 'http://central-ledger:3001/participants', list: '/data/items', id: '/attributes/code' },
        },
      },
    })[0]!;
    const body = { data: { items: [{ attributes: { code: 'p1' } }, { attributes: { code: 'p2' } }] } };
    expect(idsFrom(body, wrapped)).toEqual(['p1', 'p2']);
  });

  it('refuses a body with no array at the list pointer', () => {
    expect(() => idsFrom({ items: [] }, target)).toThrow(SourceShapeError);
  });

  it('refuses an item with no id at the id pointer', () => {
    expect(() => idsFrom([{ name: 'dfsp1' }, { title: 'x' }], target)).toThrow(/item 1 has no id/);
  });
});

describe('one sync pass', () => {
  const target = targetsOf(names)[0]!;

  it('makes the sourced rows of the resource name exactly the answered set', async () => {
    const keto = new FakeRegistry();
    keto.tuples = [
      row('Participant/gone', '__source__'),
      row('Participant/kept', '__source__'),
      row('Report/other', '__source__'),
    ];

    const result = await syncTarget(target, keto, answering([{ name: 'kept' }, { name: 'new' }]));

    expect(result.added).toEqual(['Participant/new']);
    expect(result.removed).toEqual(['Participant/gone']);
    expect(keto.tuples.map((t) => t.object).sort()).toEqual([
      'Participant/kept',
      'Participant/new',
      'Report/other',
    ]);
  });

  it('never touches a row a service provisioned', async () => {
    const keto = new FakeRegistry();
    keto.tuples = [
      row('Participant/dfsp3', '__registry__'),
      row('Participant/kept', '__source__'),
    ];

    const result = await syncTarget(target, keto, answering([{ name: 'kept' }]));

    expect(result.removed).toEqual([]);
    expect(keto.tuples).toContainEqual(row('Participant/dfsp3', '__registry__'));
  });

  it('touches nothing when the answer already matches', async () => {
    const keto = new FakeRegistry();
    keto.tuples = [row('Participant/kept', '__source__')];

    const result = await syncTarget(target, keto, answering([{ name: 'kept' }]));
    expect(result).toEqual({ added: [], removed: [] });
  });

  it('writes nothing when the answer has the wrong shape', async () => {
    const keto = new FakeRegistry();
    keto.tuples = [row('Participant/kept', '__source__')];

    await expect(syncTarget(target, keto, answering({ rows: [] }))).rejects.toThrow(SourceShapeError);
    expect(keto.tuples).toHaveLength(1);
  });
});

describe('the running sync', () => {
  it('stops a start on a shape the declaration does not match', async () => {
    const keto = new FakeRegistry();
    await expect(
      startSourceSync({ names, keto, intervalMs: 60_000, fetchImpl: answering({ not: 'a list' }) }),
    ).rejects.toThrow(SourceShapeError);
  });

  it('starts through a source that is down, keeping what the registry holds', async () => {
    const keto = new FakeRegistry();
    keto.tuples = [row('participants/kept', '__source__')];
    const sync = await startSourceSync({
      names,
      keto,
      intervalMs: 60_000,
      fetchImpl: answering({ error: 'unavailable' }, 503),
    });
    sync.stop();
    expect(keto.tuples).toHaveLength(1);
  });
});
