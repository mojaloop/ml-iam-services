import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { broken, permissionsOf, validateExclusions } from '../../src/iam/exclusions';
import { indexCatalogs, RolesFile, validateRoles } from '../../src/iam/roles';

const permission = (id: string): CatalogPermission => ({
  id,
  relation: id.split('.').slice(1).join('.'),
  operationId: id.split('.').slice(1).join('.'),
  summary: id,
  deprecated: false,
  method: 'POST',
  path: '/x',
  scopedBy: [],
  bound: [],
  resourceNames: {},
});

const catalog: ServiceCatalog = {
  service: 'settlement',
  namespace: 'settlement',
  title: 'Settlement',
  basePath: '',
  resourceTypes: [],
  permissions: [
    permission('settlement.auditSettlement'),
    permission('settlement.positionFundsInOut'),
    permission('settlement.positionNDCEdit'),
    permission('settlement.settlementView'),
  ],
};

const index = indexCatalogs([catalog]);

/** The rule this deployment actually ships: whoever moves funds may not audit the moving. */
const auditVsPosition = {
  name: 'audit-exclusion',
  a: ['settlement.auditSettlement'],
  b: ['settlement.positionFundsInOut', 'settlement.positionNDCEdit'],
};

const roles: RolesFile['roles'] = {
  'finance-manager': {
    grants: [
      { permission: 'settlement.positionFundsInOut' },
      { permission: 'settlement.positionNDCEdit' },
      { permission: 'settlement.settlementView' },
    ],
  },
  auditor: {
    grants: [{ permission: 'settlement.auditSettlement' }, { permission: 'settlement.settlementView' }],
  },
};

describe('separation of duties', () => {
  it('says nothing about either role on its own', () => {
    expect(broken(permissionsOf([roles['finance-manager']!]), [auditVsPosition])).toEqual([]);
    expect(broken(permissionsOf([roles.auditor!]), [auditVsPosition])).toEqual([]);
  });

  /**
   * The two grants are months and two admins apart, and the graph is the only
   * place their union is ever visible.
   */
  it('refuses the pair, naming the rule and both sides', () => {
    expect(broken(permissionsOf([roles['finance-manager']!, roles.auditor!]), [auditVsPosition])).toEqual([
      'audit-exclusion: settlement.auditSettlement cannot be held with settlement.positionFundsInOut,settlement.positionNDCEdit',
    ]);
  });

  it('refuses a role that carries both sides by itself', () => {
    const file: RolesFile = {
      roles: {
        ...roles,
        everything: {
          grants: [
            { permission: 'settlement.auditSettlement' },
            { permission: 'settlement.positionFundsInOut' },
          ],
        },
      },
      exclusions: [auditVsPosition],
    };
    expect(validateExclusions(file, index)).toEqual([
      'role everything breaks audit-exclusion: settlement.auditSettlement cannot be held with settlement.positionFundsInOut',
    ]);
  });

  it('refuses a seeded assignment that combines them', () => {
    const file: RolesFile = {
      roles,
      exclusions: [auditVsPosition],
      assignments: [
        { subject: 'alice', role: 'finance-manager' },
        { subject: 'alice', role: 'auditor' },
        { subject: 'bob', role: 'auditor' },
      ],
    };
    const problems = validateRoles(file, index);
    expect(problems).toEqual([
      'alice breaks audit-exclusion: settlement.auditSettlement cannot be held with settlement.positionFundsInOut,settlement.positionNDCEdit',
    ]);
  });

  /** A rule naming a permission nothing advertises would never fire, which is worse than no rule. */
  it('refuses a rule that can never match', () => {
    const file: RolesFile = {
      roles,
      exclusions: [{ name: 'typo', a: ['settlement.auditSettlment'], b: ['settlement.positionNDCEdit'] }],
    };
    expect(validateRoles(file, index)).toContain('typo: unknown permission settlement.auditSettlment');
  });

  it('refuses a one-sided rule', () => {
    const file: RolesFile = { roles, exclusions: [{ name: 'half', a: ['settlement.auditSettlement'], b: [] }] };
    expect(validateRoles(file, index)).toContain('half: both sides need at least one permission');
  });

  it('is silent when a deployment declares no rules', () => {
    expect(validateRoles({ roles, assignments: [{ subject: 'alice', role: 'auditor' }] }, index)).toEqual([]);
  });
});
