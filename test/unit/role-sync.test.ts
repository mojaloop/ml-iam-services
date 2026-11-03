import { afterEach, describe, expect, it } from 'vitest';

import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { EMPTY, History } from '../../src/iam/history';
import { membership } from '../../src/iam/materialize';
import { RoleSync, RoleView, RuleView } from '../../src/iam/role-sync';
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

const cluster = {
  roles: [] as unknown[],
  separations: [] as unknown[],
  statuses: [] as Array<{ name: string; status: Record<string, unknown> }>,
  history: EMPTY as History,
  rewritten: [] as Array<{ name: string; grants: string[] }>,
};

const setup = () => {
  const keto = new MemoryKeto(['Role', 'Resource', 'ledger']);
  let live: RolesFile | undefined;
  let waiting: RolesFile['roles'] | undefined;
  let told: { roles: RoleView[]; rules: RuleView[] } | undefined;
  const sync = new RoleSync({
    keto,
    objects: async () => ({ roles: cluster.roles as never, separations: cluster.separations as never }),
    setStatus: async (_model, _namespace, name, status) => {
      cluster.statuses.push({ name, status });
    },
    history: () => cluster.history,
    owns: (object) => object.metadata?.namespace === 'iam',
    rewrite: async (object, grants) => {
      cluster.rewritten.push({ name: object.metadata!.name!, grants: grants.map((g) => g.permission) });
    },
    catalog: () => catalog,
    own: () => new Set(),
    ready: async () => undefined,
    namespacesOf: () => [],
    exclusive: (write) => write(),
    onApplied: (applied, _result, _pending, roles) => {
      live = applied;
      waiting = roles;
    },
    onTold: (roles, rules) => {
      told = { roles, rules };
    },
  });
  return { keto, sync, live: () => live, waiting: () => waiting, told: () => told };
};

describe('keeping the roles applied', () => {
  afterEach(() => {
    cluster.roles = [];
    cluster.separations = [];
    cluster.statuses = [];
    cluster.history = EMPTY;
    cluster.rewritten = [];
  });

  it('holds a grant under the new name of a renamed permission, and says so', async () => {
    cluster.roles = [role('reader', ['ledger.fetch'])];
    cluster.history = { known: {}, renamed: { 'ledger.fetch': 'ledger.read' }, removed: [] };
    const { keto, sync, live } = setup();

    await sync.run();

    expect(live()!.roles['reader']!.grants.map((g) => g.permission)).toEqual(['ledger.read']);
    expect(keto.tuples.map((t) => t.relation)).toEqual(['read']);
    expect(verdict('reader')).toMatchObject({ warnings: ['ledger.fetch is now ledger.read; the grant holds under the new name'] });
    expect(cluster.rewritten).toEqual([]);
  });

  it('drops the grant of a removed permission and keeps the rest of the role', async () => {
    cluster.roles = [role('reader', ['ledger.read', 'ledger.purge'])];
    cluster.history = { known: {}, renamed: {}, removed: ['ledger.purge'] };
    const { sync, live } = setup();

    await sync.run();

    expect(live()!.roles['reader']!.grants.map((g) => g.permission)).toEqual(['ledger.read']);
    expect(verdict('reader')?.conditions[0]).toMatchObject({ reason: 'Accepted' });
    expect(verdict('reader')).toMatchObject({ warnings: ['ledger.purge was removed from ledger; its grant is dropped'] });
  });

  it('moves a role it keeps itself to the new name', async () => {
    cluster.roles = [role('composed', ['ledger.fetch'], 'iam')];
    cluster.history = { known: {}, renamed: { 'ledger.fetch': 'ledger.read' }, removed: [] };
    const { sync } = setup();

    await sync.run();

    expect(cluster.rewritten).toEqual([{ name: 'composed', grants: ['ledger.read'] }]);
  });

  it('still refuses a permission the deployment never had', async () => {
    cluster.roles = [role('typo', ['ledger.raed'])];
    cluster.history = { known: {}, renamed: { 'ledger.fetch': 'ledger.read' }, removed: ['ledger.purge'] };
    const { sync } = setup();

    await sync.run();

    expect(verdict('typo')?.conditions[0]).toMatchObject({ reason: 'Refused' });
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
    const { keto, sync, waiting } = setup();

    await sync.run();

    expect(keto.tuples).toEqual([]);
    expect(Object.keys(waiting()!)).toEqual(['payer']);
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

  it('tells the composition what became of every object, the refused one included', async () => {
    cluster.roles = [
      role('reader', ['ledger.write'], 'mcm', '2026-10-02T00:00:00Z'),
      role('reader', ['ledger.read'], 'ory', '2026-10-01T00:00:00Z'),
      role('operator', ['ledger.get']),
    ];
    const { sync, told } = setup();

    await sync.run();

    expect(told()!.roles.map((r) => [r.namespace, r.name, r.ready.reason, r.open])).toEqual(
      expect.arrayContaining([
        ['mcm', 'reader', 'Refused', []],
        ['ory', 'reader', 'Accepted', []],
        [expect.any(String), 'operator', 'Accepted', ['participant']],
      ]),
    );
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
