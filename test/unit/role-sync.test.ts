import { afterEach, describe, expect, it, vi } from 'vitest';

import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { membership } from '../../src/iam/materialize';

const cluster = vi.hoisted(() => ({
  roles: [] as unknown[],
  separations: [] as unknown[],
  statuses: [] as Array<{ name: string; status: Record<string, unknown> }>,
}));

vi.mock('../../src/operator/cluster', () => ({
  AuthzRole: class AuthzRole {},
  AuthzSeparation: class AuthzSeparation {},
  listRoles: vi.fn(async () => cluster.roles),
  listSeparations: vi.fn(async () => cluster.separations),
  setStatus: vi.fn(async (_model: unknown, _namespace: string, name: string, status: Record<string, unknown>) => {
    cluster.statuses.push({ name, status });
  }),
}));

import { RoleSync } from '../../src/iam/role-sync';
import { RolesFile } from '../../src/iam/roles';
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

const catalog: ServiceCatalog[] = [
  {
    service: 'ledger',
    namespace: 'ledger',
    title: 'Ledger',
    basePath: '',
    resourceTypes: ['participants'],
    permissions: [permission('ledger.read'), permission('ledger.write'), permission('ledger.get', ['participants'])],
  },
];

const role = (name: string, grants: string[], namespace = 'ory', created = '2026-10-01T00:00:00Z') => ({
  metadata: { name, namespace, generation: 1, creationTimestamp: created },
  spec: { grants: grants.map((permission) => ({ permission })) },
});

const verdict = (name: string) =>
  [...cluster.statuses].reverse().find((s) => s.name === name)?.status as
    | { conditions: Array<{ reason: string; message: string }>; open?: string[]; violations?: string[] }
    | undefined;

const setup = () => {
  const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
  let live: RolesFile | undefined;
  const sync = new RoleSync({
    keto,
    catalog: () => catalog,
    ready: async () => undefined,
    namespacesOf: () => [],
    onApplied: (applied) => {
      live = applied;
    },
  });
  return { keto, sync, live: () => live };
};

describe('keeping the roles applied', () => {
  afterEach(() => {
    cluster.roles = [];
    cluster.separations = [];
    cluster.statuses = [];
  });

  it('applies a valid role and says what an assignment must name', async () => {
    cluster.roles = [role('reader', ['ledger.read']), role('operator', ['ledger.get'])];
    const { keto, sync, live } = setup();

    await sync.run();

    expect(Object.keys(live()!.roles).sort()).toEqual(['operator', 'reader']);
    expect(keto.tuples.some((t) => t.subject_set?.object === 'reader')).toBe(true);
    expect(verdict('reader')?.conditions[0]).toMatchObject({ reason: 'Accepted' });
    expect(verdict('operator')?.open).toEqual(['participant']);
  });

  it('holds nothing for a role that is refused or waits, and says why', async () => {
    cluster.roles = [role('typo', ['ledger.raed']), role('payer', ['payouts.create'])];
    const { keto, sync } = setup();

    await sync.run();

    expect(keto.tuples).toEqual([]);
    expect(verdict('typo')?.conditions[0]).toMatchObject({ reason: 'Refused', message: 'typo: unknown permission ledger.raed' });
    expect(verdict('payer')?.conditions[0]).toMatchObject({ reason: 'Waiting', message: 'waits for payouts' });
  });

  it('applies the oldest of two objects claiming one name, and refuses the other', async () => {
    cluster.roles = [
      role('reader', ['ledger.write'], 'mcm', '2026-10-02T00:00:00Z'),
      role('reader', ['ledger.read'], 'ory', '2026-10-01T00:00:00Z'),
    ];
    const { keto, sync } = setup();

    await sync.run();

    expect(keto.tuples.map((t) => t.relation)).toEqual(['read']);
    const refused = cluster.statuses.find((s) => (s.status.conditions as Array<{ reason: string }>)[0]!.reason === 'Refused');
    expect((refused?.status.conditions as Array<{ message: string }>)[0]!.message).toContain('already defined by AuthzRole/ory/reader');
  });

  it('lists the subjects a new rule finds holding both groups, and takes nothing away', async () => {
    cluster.roles = [role('reader', ['ledger.read']), role('writer', ['ledger.write'])];
    const { keto, sync } = setup();
    await sync.run();
    keto.tuples.push(membership('reader', 'alice'), membership('writer', 'alice'), membership('reader', 'bob'));

    cluster.separations = [
      { metadata: { name: 'read-or-write', namespace: 'ory', generation: 1 }, spec: { groups: [['ledger.read'], ['ledger.write']] } },
    ];
    await sync.run();

    expect(verdict('read-or-write')?.violations).toEqual(['alice']);
    expect(keto.tuples.filter((t) => t.subject_id === 'alice')).toHaveLength(2);
  });

  it('writes nothing to Keto when nothing changed', async () => {
    cluster.roles = [role('reader', ['ledger.read'])];
    const { keto, sync } = setup();
    await sync.run();
    const patches = keto.patches;

    await sync.run();

    expect(keto.patches).toBe(patches);
  });
});
