import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { membership, roleObject } from '../../src/iam/materialize';
import { ownResources, recordOwn } from '../../src/iam/own';
import { Provisioner } from '../../src/iam/provisioner';
import { MemoryKeto } from './memory-keto';

const permission = (id: string, resourceNames: Record<string, string> = {}): CatalogPermission => ({
  id,
  relation: id.split('.')[1]!,
  operationId: id.split('.')[1]!,
  summary: id,
  deprecated: false,
  method: 'GET',
  path: '/x',
  scopedBy: Object.keys(resourceNames),
  bound: [],
  resourceNames,
});

const catalog: ServiceCatalog[] = [
  {
    service: 'iam',
    namespace: 'iam',
    title: 'IAM',
    basePath: '',
    resourceTypes: ['roles', 'permissions'],
    permissions: [permission('iam.assignRole', { roles: 'role' }), permission('iam.createRole', { permissions: 'permission' })],
  },
  { service: 'ledger', namespace: 'ledger', title: 'Ledger', basePath: '', resourceTypes: [], permissions: [permission('ledger.read')] },
];

const names = {
  resourceNames: {
    role: { members: [{ service: 'iam', type: 'roles' }] },
    permission: { members: [{ service: 'iam', type: 'permissions' }] },
  },
};

describe('the IAM recording its own resources', () => {
  it('records its roles and every composed permission under the names its document is given', () => {
    expect(ownResources(catalog, 'iam', ['reader', 'admin'])).toEqual(
      new Map([
        ['role', ['admin', 'reader']],
        ['permission', ['iam.assignRole', 'iam.createRole', 'ledger.read']],
      ]),
    );
  });

  it('records nothing for a prefix that is not composed', () => {
    expect(ownResources(catalog, 'elsewhere', ['reader'])).toEqual(new Map());
  });

  it('adds what is new and retires what is gone, with every instance over it', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'iam', 'ledger']);
    const provisioner = new Provisioner(keto, { roles: {} }, new Map(), names);
    await recordOwn(provisioner, new Map([['role', ['reader', 'writer']]]));
    keto.tuples.push(membership('role-admin', 'alice', { role: 'writer' }));

    await recordOwn(provisioner, new Map([['role', ['reader', 'checker']]]));

    expect((await provisioner.resources('role')).map((r) => r.id)).toEqual(['checker', 'reader']);
    expect(keto.tuples.some((t) => t.object === roleObject('role-admin', { role: 'writer' }))).toBe(false);
  });

  it('retires every id that is gone in one write, however many', async () => {
    const keto = new MemoryKeto(['Role', 'Resource', 'iam', 'ledger']);
    const provisioner = new Provisioner(keto, { roles: {} }, new Map(), names);
    await recordOwn(provisioner, new Map([['role', ['reader', 'writer', 'auditor', 'checker']]]));
    keto.tuples.push(membership('role-admin', 'alice', { role: 'writer' }), membership('role-admin', 'bob', { role: 'auditor' }));
    const patch = vi.spyOn(keto, 'patch');

    await recordOwn(provisioner, new Map([['role', ['reader']]]));

    expect(patch).toHaveBeenCalledTimes(1);
    expect((await provisioner.resources('role')).map((r) => r.id)).toEqual(['reader']);
    expect(keto.tuples.filter((t) => t.namespace === 'Role')).toEqual([]);
  });
});
