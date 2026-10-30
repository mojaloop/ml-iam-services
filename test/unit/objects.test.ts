import { readyCondition } from '../../src/iam/conditions';
import { claimNames, resourceNamesOf, rolesFileOf, writeStatus } from '../../src/iam/objects';

const at = (iso: string) => ({ creationTimestamp: iso });

describe('a name across the cluster', () => {
  it('belongs to its oldest object, and a later one elsewhere is refused', () => {
    const first = { metadata: { name: 'reader', namespace: 'ory', ...at('2026-10-01T00:00:00Z') } };
    const later = { metadata: { name: 'reader', namespace: 'mcm', ...at('2026-10-02T00:00:00Z') } };
    const other = { metadata: { name: 'writer', namespace: 'mcm', ...at('2026-10-03T00:00:00Z') } };

    const { owners, refused } = claimNames('AuthzRole', [later, other, first]);

    expect(owners).toEqual([first, other]);
    expect(refused.get(later)).toBe(
      'reader is already defined by AuthzRole/ory/reader; a name is unique across the cluster',
    );
  });
});

describe('objects into deployment data', () => {
  it('keys roles and rules by object name, a rule comparing within a subject unless it says otherwise', () => {
    const file = rolesFileOf(
      [{ metadata: { name: 'signed-in' }, spec: { heldBy: 'authenticated', grants: [{ permission: 'iam.me' }] } }],
      [{ metadata: { name: 'four-eyes' }, spec: { groups: [['a.x'], ['a.y']] } }],
    );
    expect(file).toEqual({
      roles: { 'signed-in': { heldBy: 'authenticated', grants: [{ permission: 'iam.me' }] } },
      exclusions: [{ name: 'four-eyes', groups: [['a.x'], ['a.y']], within: 'subject' }],
    });
  });

  it('keys resource names by object name, keeping labels as written', () => {
    expect(
      resourceNamesOf([
        {
          metadata: { name: 'participant' },
          spec: { label: { en: 'Participant' }, members: [{ service: 'ledger', type: 'participants' }] },
        },
      ]),
    ).toEqual({
      resourceNames: {
        participant: { label: { en: 'Participant' }, members: [{ service: 'ledger', type: 'participants' }] },
      },
    });
  });
});

describe('writing a status', () => {
  const accepted = { reason: 'Accepted' as const, message: '3 grants' };

  it('keeps the transition time while the status holds, and moves it when the status changes', () => {
    const before = [readyCondition(undefined, accepted, 1, '2026-10-01T00:00:00.000Z')];
    expect(readyCondition(before, { reason: 'Accepted', message: '4 grants' }, 2, 'later').lastTransitionTime).toBe(
      '2026-10-01T00:00:00.000Z',
    );
    expect(readyCondition(before, { reason: 'Refused', message: 'typo' }, 2, 'later').lastTransitionTime).toBe('later');
  });

  it('writes nothing when the object already says it', async () => {
    const writes: unknown[] = [];
    const object = {
      metadata: { name: 'reader', namespace: 'ory', generation: 1 },
      status: {
        observedGeneration: 1,
        conditions: [readyCondition(undefined, accepted, 1, '2026-10-01T00:00:00.000Z')],
        open: [],
      },
    };

    await writeStatus(object, accepted, { open: [] }, async (_, __, status) => void writes.push(status));
    expect(writes).toEqual([]);

    await writeStatus(object, accepted, { open: ['participant'] }, async (_, __, status) => void writes.push(status));
    expect(writes).toEqual([expect.objectContaining({ open: ['participant'] })]);
  });
});
