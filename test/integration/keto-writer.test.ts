import { KetoWriter, filterFor } from '../../src/iam/keto';
import { MEMBERS, ROLE_NAMESPACE, Tuple } from '../../src/iam/materialize';

const KETO_WRITE_URL = process.env.KETO_WRITE_URL || 'http://localhost:4467';
const KETO_READ_URL = process.env.KETO_READ_URL || 'http://localhost:4466';

const NAMESPACE = ROLE_NAMESPACE;

const grant = (object: string, subject: string): Tuple => ({
  namespace: NAMESPACE,
  object,
  relation: MEMBERS,
  subject_id: subject,
});

describe('the Keto client against a running Keto', () => {
  const keto = new KetoWriter(KETO_WRITE_URL, KETO_READ_URL);

  afterEach(async () => {
    for (const object of ['writer-a', 'writer-b']) {
      await keto.deleteWhere({ namespace: NAMESPACE, object, relation: MEMBERS });
    }
  });

  it('reads the namespaces Keto holds', async () => {
    await expect(keto.namespaces()).resolves.toContain(NAMESPACE);
  });

  it('writes a tuple and reads it back', async () => {
    await keto.put(grant('writer-a', 'user-1'));

    const held = await keto.query({ namespace: NAMESPACE, object: 'writer-a', relation: MEMBERS });

    expect(held).toHaveLength(1);
    expect(held[0]).toMatchObject({ namespace: NAMESPACE, object: 'writer-a', subject_id: 'user-1' });
  });

  it('leaves one row for a tuple written twice', async () => {
    await keto.put(grant('writer-a', 'user-1'));
    await keto.put(grant('writer-a', 'user-1'));

    const held = await keto.query({ namespace: NAMESPACE, object: 'writer-a', relation: MEMBERS });

    expect(held).toHaveLength(1);
  });

  it('deletes exactly the tuple a filter names', async () => {
    await keto.putAll([grant('writer-a', 'user-1'), grant('writer-a', 'user-2'), grant('writer-b', 'user-1')]);

    await keto.deleteWhere(filterFor(grant('writer-a', 'user-1')));

    const a = await keto.query({ namespace: NAMESPACE, object: 'writer-a', relation: MEMBERS });
    const b = await keto.query({ namespace: NAMESPACE, object: 'writer-b', relation: MEMBERS });
    expect(a.map((t) => t.subject_id)).toEqual(['user-2']);
    expect(b).toHaveLength(1);
  });

  // Keto answers 100 tuples a page and a token for the rest, so this crosses
  // the boundary: reading one page would return 100 of the 120.
  it('follows pagination to the end', async () => {
    const subjects = Array.from({ length: 120 }, (_, i) => `user-${i}`);
    await keto.putAll(subjects.map((s) => grant('writer-b', s)));

    const held = await keto.query({ namespace: NAMESPACE, object: 'writer-b', relation: MEMBERS });

    expect(held).toHaveLength(120);
    expect(new Set(held.map((t) => t.subject_id))).toEqual(new Set(subjects));
  });
});
