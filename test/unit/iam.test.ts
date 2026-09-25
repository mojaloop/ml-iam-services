import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { materialize, materializeRole, roleObject } from '../../src/iam/materialize';
import { provision } from '../../src/iam/provision';
import { indexCatalogs, openResourceNames, readyRoles, RolesFile, validateRoles } from '../../src/iam/roles';

const NAMES: Record<string, string> = { widgets: 'Widget', reports: 'Report' };

const permission = (id: string, scopedBy: string[] = [], bound: string[] = []): CatalogPermission => ({
  id,
  relation: id.split('.').slice(1).join('.'),
  operationId: id.split('.').slice(1).join('.'),
  summary: id,
  deprecated: false,
  method: 'GET',
  path: '/x',
  scopedBy,
  bound,
  resourceNames: Object.fromEntries(scopedBy.map((type) => [type, NAMES[type]!])),
});

const catalog: ServiceCatalog = {
  service: 'example',
  namespace: 'example',
  title: 'Example',
  basePath: '',
  resourceTypes: ['widgets', 'reports'],
  permissions: [
    permission('example.getWidgetCa', ['widgets'], ['widgets']),
    permission('example.issueCert', ['widgets'], ['widgets']),
    permission('example.getWidgets', ['widgets'], []),
    permission('example.getRegions'),
    permission('example.getReportRows', ['reports', 'widgets'], ['reports', 'widgets']),
  ],
};

const index = indexCatalogs([catalog]);
const check = (file: RolesFile) => validateRoles(file, index);

describe('roles waiting for their services', () => {
  const file: RolesFile = {
    roles: {
      reader: { grants: [{ permission: 'example.getRegions' }] },
      operator: { grants: [{ permission: 'example.getWidgetCa' }, { permission: 'ledger.getPositions' }] },
    },
    assignments: [
      { subject: 'alice', role: 'reader' },
      { subject: 'bob', role: 'operator', resources: { Widget: 'w1' } },
      { subject: 'carol', role: 'nobody' },
    ],
    exclusions: [
      { name: 'regions-vs-ca', a: ['example.getRegions'], b: ['example.getWidgetCa'] },
      { name: 'regions-vs-positions', a: ['example.getRegions'], b: ['ledger.getPositions'] },
    ],
  };

  it('holds back a role, its assignments and exclusions until every service it names is composed', () => {
    const ready = readyRoles(file, [catalog]);
    expect(Object.keys(ready.file.roles)).toEqual(['reader']);
    expect(ready.file.assignments?.map((a) => a.subject)).toEqual(['alice', 'carol']);
    expect(ready.file.exclusions?.map((e) => e.name)).toEqual(['regions-vs-ca']);
    expect(ready.pending).toEqual([
      'role operator waits for ledger',
      'exclusion regions-vs-positions waits for ledger',
    ]);
    expect(validateRoles(ready.file, index)).toEqual(['assignment for carol: unknown role nobody']);
  });

  it('lets them go live once the service arrives', () => {
    const ledger: ServiceCatalog = {
      ...catalog,
      service: 'ledger',
      namespace: 'ledger',
      permissions: [permission('ledger.getPositions')],
    };
    const ready = readyRoles(file, [catalog, ledger]);
    expect(Object.keys(ready.file.roles)).toEqual(['reader', 'operator']);
    expect(ready.pending).toEqual([]);
  });

  it('still refuses an operation a composed service does not have', () => {
    const typo: RolesFile = { roles: { r: { grants: [{ permission: 'example.getRegionz' }] } } };
    const ready = readyRoles(typo, [catalog]);
    expect(ready.pending).toEqual([]);
    expect(validateRoles(ready.file, index)).toEqual(['r: unknown permission example.getRegionz']);
  });
});

describe('role validation', () => {
  it('accepts grants that name resources or leave the name for the assignment', () => {
    expect(
      check({
        roles: {
          auditor: {
            grants: [
              { permission: 'example.getWidgets', resources: { Widget: 'all' } },
              { permission: 'example.getWidgetCa' },
            ],
          },
        },
      }),
    ).toEqual([]);
  });

  it('rejects a resource name the permission is not scoped by', () => {
    expect(
      check({ roles: { r: { grants: [{ permission: 'example.getRegions', resources: { Widget: 'all' } }] } } }),
    ).toEqual(['r: example.getRegions names Widget, which does not scope it']);
  });

  it('rejects an empty id', () => {
    expect(
      check({ roles: { r: { grants: [{ permission: 'example.getWidgetCa', resources: { Widget: '' } }] } } }),
    ).toEqual(['r: example.getWidgetCa names an empty Widget id']);
  });

  it('rejects an unknown permission', () => {
    expect(check({ roles: { r: { grants: [{ permission: 'example.gone' }] } } })).toEqual([
      'r: unknown permission example.gone',
    ]);
  });

  it('derives what a role leaves open, for its assignments to fill', () => {
    const role = {
      grants: [
        { permission: 'example.getReportRows', resources: { Report: 'all' } },
        { permission: 'example.getRegions' },
      ],
    };
    expect(openResourceNames(role, index)).toEqual(['Widget']);
    expect(openResourceNames({ grants: [{ permission: 'example.getRegions' }] }, index)).toEqual([]);
  });

  it('rejects an assignment whose resources are not the ones the role leaves open', () => {
    expect(
      check({
        roles: { r: { grants: [{ permission: 'example.issueCert' }] } },
        assignments: [{ subject: 'u1', role: 'r' }],
      }),
    ).toEqual(['assignment for u1: role r takes [Widget], got []']);
  });

  it('reports every problem at once', () => {
    expect(
      check({
        roles: {
          r: {
            grants: [{ permission: 'example.gone' }, { permission: 'example.getRegions', resources: { Widget: 'all' } }],
          },
        },
      }),
    ).toHaveLength(2);
  });
});

describe('materialization', () => {
  it('names a closed role by itself and an instance by its resources', () => {
    expect(roleObject('auditor')).toBe('auditor');
    expect(roleObject('operator', { Widget: 'w7', Tenant: 'acme' })).toBe('operator@Tenant=acme,Widget=w7');
  });

  it('writes the singleton for a permission whose path binds nothing', () => {
    const tuples = materializeRole(
      'auditor',
      { grants: [{ permission: 'example.getWidgets', resources: { Widget: 'all' } }] },
      index,
    );
    expect(tuples[0]).toEqual({
      namespace: 'example',
      object: '__self__',
      relation: 'getWidgets',
      subject_set: { namespace: 'Role', object: 'auditor', relation: 'members' },
    });
  });

  it('writes the resource-name-wide object for an all setting', () => {
    const tuples = materializeRole(
      'admin',
      { grants: [{ permission: 'example.getWidgetCa', resources: { Widget: 'all' } }] },
      index,
    );
    expect(tuples[0]!.object).toBe('Widget/__all__');
  });

  it('writes one tuple per id in a list setting', () => {
    const tuples = materializeRole(
      'west',
      { grants: [{ permission: 'example.getWidgetCa', resources: { Widget: ['w7', 'w11'] } }] },
      index,
    );
    expect(tuples.map((t) => t.object)).toEqual(['Widget/w7', 'Widget/w11']);
  });

  it('writes the checked object first and the resources it may see after it', () => {
    const tuples = materializeRole(
      'r',
      { grants: [{ permission: 'example.getWidgets', resources: { Widget: ['w7', 'w11'] } }] },
      index,
    );
    expect(tuples.map((t) => t.object)).toEqual(['__self__', 'Widget/w7', 'Widget/w11']);
    expect(tuples.every((t) => t.relation === 'getWidgets')).toBe(true);
  });

  it('writes one tuple per bound resource for a multi-resource permission', () => {
    const tuples = materializeRole(
      'r',
      { grants: [{ permission: 'example.getReportRows', resources: { Report: 'r1', Widget: 'w7' } }] },
      index,
    );
    expect(tuples.map((t) => t.object)).toEqual(['Report/r1', 'Widget/w7']);
  });

  it('collapses two grants that reach the same object and relation', () => {
    const tuples = materializeRole(
      'r',
      {
        grants: [
          { permission: 'example.getWidgetCa', resources: { Widget: ['w7', 'w7'] } },
          { permission: 'example.getWidgetCa', resources: { Widget: 'w7' } },
        ],
      },
      index,
    );
    expect(tuples).toHaveLength(1);
  });

  it('leaves a role with an open resource name unmaterialized until an assignment', () => {
    const file: RolesFile = {
      roles: { operator: { grants: [{ permission: 'example.issueCert' }] } },
    };
    expect(materialize(file, index)).toEqual([]);
  });

  it('instantiates an open role per assignment and adds the member', () => {
    const file: RolesFile = {
      roles: { operator: { grants: [{ permission: 'example.issueCert' }] } },
      assignments: [
        { subject: 'u1', role: 'operator', resources: { Widget: 'w7' } },
        { subject: 'u2', role: 'operator', resources: { Widget: 'w11' } },
      ],
    };
    const tuples = materialize(file, index);
    expect(tuples.map((t) => `${t.object}#${t.relation}@${t.subject_id ?? t.subject_set!.object}`)).toEqual([
      'Widget/w7#issueCert@operator@Widget=w7',
      'operator@Widget=w7#members@u1',
      'Widget/w11#issueCert@operator@Widget=w11',
      'operator@Widget=w11#members@u2',
    ]);
  });

  it('never writes a grant straight to a user', () => {
    const file: RolesFile = {
      roles: {
        admin: {
          grants: [
            { permission: 'example.getWidgetCa', resources: { Widget: 'all' } },
            { permission: 'example.getRegions' },
          ],
        },
        operator: { grants: [{ permission: 'example.issueCert' }] },
      },
      assignments: [{ subject: 'u1', role: 'operator', resources: { Widget: 'w7' } }],
    };
    const grants = materialize(file, index).filter((t) => t.namespace !== 'Role');
    expect(grants.every((t) => t.subject_id === undefined && t.subject_set !== undefined)).toBe(true);
  });
});

describe('provisioning a resource', () => {
  it('records only that the resource exists, keyed by the resource name', () => {
    const tuples = provision('Widget', 'w7');
    expect(tuples).toHaveLength(1);
    expect(tuples[0]).toMatchObject({ object: 'Widget/w7' });
  });
});
