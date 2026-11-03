import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { describe as name } from '../../src/iam/keto';
import { heldByMarker, membership, Tuple } from '../../src/iam/materialize';
import { Provisioner } from '../../src/iam/provisioner';
import { applyRoles } from '../../src/iam/reconcile';
import { indexCatalogs, RolesFile } from '../../src/iam/roles';
import { MemoryKeto } from './memory-keto';

const permission = (id: string, scopedBy: string[] = []): CatalogPermission => ({
  id,
  relation: id.split('.')[1]!,
  operationId: id.split('.')[1]!,
  summary: id,
  deprecated: false,
  method: 'GET',
  path: '/x',
  scopedBy,
  bound: scopedBy,
  resourceNames: Object.fromEntries(scopedBy.map((type) => [type, 'participant'])),
});

const catalog: ServiceCatalog = {
  service: 'ledger',
  namespace: 'ledger',
  title: 'Ledger',
  basePath: '',
  resourceTypes: ['participants'],
  permissions: [
    permission('ledger.read'),
    permission('ledger.write'),
    permission('ledger.audit'),
    permission('ledger.getParticipant', ['participants']),
  ],
};
const index = indexCatalogs([catalog]);

const rolesOf = (roles: RolesFile['roles']): RolesFile => ({ roles });
const keys = (tuples: Tuple[]) => tuples.map(name).sort();

const grant = (object: string, relation: string, role: string): Tuple => ({
  namespace: 'ledger',
  object,
  relation,
  subject_set: { namespace: 'Role', object: role, relation: 'members' },
});

describe('applying the roles to Keto', () => {
  it('writes every role in a single patch', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);

    await applyRoles(
      keto,
      rolesOf({
        reader: { grants: [{ permission: 'ledger.read' }] },
        writer: { grants: [{ permission: 'ledger.write' }, { permission: 'ledger.audit' }] },
      }),
      index,
    );

    expect(keto.patches).toBe(1);
    expect(keys(keto.tuples)).toEqual(
      keys([
        grant('$self', 'read', 'reader'),
        grant('$self', 'write', 'writer'),
        grant('$self', 'audit', 'writer'),
      ]),
    );
  });

  it('leaves a grant the role still has untouched, and removes only the one it lost', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    const kept = grant('$self', 'read', 'reader');
    keto.tuples = [kept, grant('$self', 'write', 'reader')];

    const applied = await applyRoles(keto, rolesOf({ reader: { grants: [{ permission: 'ledger.read' }] } }), index);

    expect(applied).toMatchObject({ inserted: 0, deleted: 1 });
    expect(keto.tuples).toEqual([kept]);
  });

  it('takes every grant away from a role that is no longer live', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    keto.tuples = [grant('$self', 'write', 'retired'), grant('$self', 'read', 'reader')];

    await applyRoles(keto, rolesOf({ reader: { grants: [{ permission: 'ledger.read' }] } }), index);

    expect(keys(keto.tuples)).toEqual(keys([grant('$self', 'read', 'reader')]));
  });

  it('applied twice, holds one row per grant and per membership', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    const file: RolesFile = {
      roles: { reader: { grants: [{ permission: 'ledger.read' }] } },
      assignments: [{ subject: 'alice', role: 'reader' }],
    };

    await applyRoles(keto, file, index);
    await applyRoles(keto, file, index);

    expect(keto.tuples).toHaveLength(2);
    expect(keto.tuples).toContainEqual(membership('reader', 'alice'));
  });

  it('keeps the grants of an instance someone holds, refreshed from its role', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    const instance = 'operator@participant=dfsp1';
    keto.tuples = [
      membership('operator', 'bob', { participant: 'dfsp1' }),
      grant('participant/dfsp1', 'read', instance),
    ];

    await applyRoles(keto, rolesOf({ operator: { grants: [{ permission: 'ledger.getParticipant' }] } }), index);

    expect(keys(keto.tuples)).toEqual(
      keys([membership('operator', 'bob', { participant: 'dfsp1' }), grant('participant/dfsp1', 'getParticipant', instance)]),
    );
  });

  it('leaves grants in a namespace the model no longer declares alone', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    const retired: Tuple = { ...grant('$self', 'view', 'reader'), namespace: 'gone' };
    keto.tuples = [retired];

    await applyRoles(keto, rolesOf({ reader: { grants: [{ permission: 'ledger.read' }] } }), index);

    expect(keto.tuples).toContainEqual(retired);
  });

  it('marks a role every subject holds in the same patch as its grants, and unmarks one that stops being', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    keto.tuples = [heldByMarker('former')];

    await applyRoles(
      keto,
      rolesOf({
        'signed-in': { heldBy: 'authenticated', grants: [{ permission: 'ledger.read' }] },
        former: { grants: [{ permission: 'ledger.write' }] },
      }),
      index,
    );

    expect(keto.patches).toBe(1);
    expect(keys(keto.tuples)).toEqual(
      keys([heldByMarker('signed-in'), grant('$self', 'read', 'signed-in'), grant('$self', 'write', 'former')]),
    );
  });

  it('names the members of every role whose grants it changed, and nobody when nothing changed', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    keto.tuples = [membership('reader', 'alice'), membership('writer', 'bob')];
    const roles = (readerGrant: string) =>
      rolesOf({ reader: { grants: [{ permission: readerGrant }] }, writer: { grants: [{ permission: 'ledger.write' }] } });

    expect((await applyRoles(keto, roles('ledger.read'), index)).affected).toEqual({ everyone: false, subjects: ['alice', 'bob'] });
    expect((await applyRoles(keto, roles('ledger.audit'), index)).affected).toEqual({ everyone: false, subjects: ['alice'] });
    expect((await applyRoles(keto, roles('ledger.audit'), index)).affected).toEqual({ everyone: false, subjects: [] });
  });

  it('names everyone when a role every signed-in subject holds is marked or its grants change', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    const signedIn = (permission: string) => rolesOf({ 'signed-in': { heldBy: 'authenticated', grants: [{ permission }] } });

    expect((await applyRoles(keto, signedIn('ledger.read'), index)).affected.everyone).toBe(true);
    expect((await applyRoles(keto, signedIn('ledger.read'), index)).affected.everyone).toBe(false);
    expect((await applyRoles(keto, signedIn('ledger.write'), index)).affected.everyone).toBe(true);
  });
});

describe('one patch', () => {
  it('refuses to insert and delete the same tuple, which would leave it with no row', async () => {
    const keto = new MemoryKeto(['Role', 'ledger']);
    const tuple = grant('$self', 'read', 'reader');
    keto.tuples = [tuple];

    await expect(keto.patch([tuple], [tuple])).rejects.toThrow(/inserts and deletes/);
    expect(keto.tuples).toEqual([tuple]);
    expect(keto.patches).toBe(0);
  });
});

describe('assigning through the IAM', () => {
  const roles = rolesOf({ operator: { grants: [{ permission: 'ledger.getParticipant' }] } });

  it('writes the instance and the membership in one patch, and a repeat adds nothing', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    keto.tuples = [{ namespace: 'Resource', object: 'participant/dfsp1', relation: 'exists', subject_id: '$registry' }];
    const provisioner = new Provisioner(keto, roles, index, {
      resourceNames: { participant: { members: [{ service: 'ledger', type: 'participants' }] } },
    });

    await provisioner.assign('alice', { role: 'operator', resources: { participant: 'dfsp1' } });
    expect(keto.patches).toBe(1);
    await provisioner.assign('alice', { role: 'operator', resources: { participant: 'dfsp1' } });

    expect(keto.patches).toBe(1);
    expect(keto.tuples).toHaveLength(3);
  });

  it('retires a resource in one patch: its instances, their members and its registry row', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    const provisioner = new Provisioner(keto, roles, index, {
      resourceNames: { participant: { members: [{ service: 'ledger', type: 'participants' }] } },
    });
    await provisioner.provision({ resourceName: 'participant', id: 'dfsp1' });
    await provisioner.assign('alice', { role: 'operator', resources: { participant: 'dfsp1' } });
    const before = keto.patches;

    const result = await provisioner.deprovision({ resourceName: 'participant', id: 'dfsp1' });

    expect(keto.patches - before).toBe(1);
    expect(keto.tuples).toEqual([]);
    expect(result.orphaned).toEqual(['alice']);
  });

  it('names as orphaned only the members holding nothing over any other resource', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
    const provisioner = new Provisioner(keto, roles, index, {
      resourceNames: { participant: { members: [{ service: 'ledger', type: 'participants' }] } },
    });
    await provisioner.provision({ resourceName: 'participant', id: 'dfsp1' });
    await provisioner.provision({ resourceName: 'participant', id: 'dfsp2' });
    await provisioner.assign('alice', { role: 'operator', resources: { participant: 'dfsp1' } });
    await provisioner.assign('bob', { role: 'operator', resources: { participant: 'dfsp1' } });
    await provisioner.assign('bob', { role: 'operator', resources: { participant: 'dfsp2' } });

    const result = await provisioner.deprovision({ resourceName: 'participant', id: 'dfsp1' });

    expect(result.orphaned).toEqual(['alice']);
    expect(await provisioner.assignments('bob')).toEqual([{ role: 'operator', resources: { participant: 'dfsp2' } }]);
  });
});
