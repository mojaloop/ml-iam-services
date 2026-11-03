import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { broken, Exclusion, Holding, ruleProblems, validateExclusions } from '../../src/iam/exclusions';
import { indexCatalogs, RoleDocument, RolesFile, validateRoles } from '../../src/iam/roles';

const permission = (id: string, scopedBy: string[] = []): CatalogPermission => ({
  id,
  relation: id.split('.').slice(1).join('.'),
  operationId: id.split('.').slice(1).join('.'),
  summary: id,
  deprecated: false,
  method: 'POST',
  path: '/x',
  scopedBy,
  bound: scopedBy,
  resourceNames: Object.fromEntries(scopedBy.map((type) => [type, 'participant'])),
});

const catalog: ServiceCatalog = {
  service: 'settlement',
  namespace: 'settlement',
  title: 'Settlement',
  basePath: '',
  resourceTypes: ['participants'],
  permissions: [
    permission('settlement.auditSettlement'),
    permission('settlement.positionFundsInOut'),
    permission('settlement.positionNDCEdit'),
    permission('settlement.settlementView'),
    permission('settlement.createPayout', ['participants']),
    permission('settlement.approvePayout', ['participants']),
  ],
};

const index = indexCatalogs([catalog]);

/** Whoever moves funds may not audit the moving. */
const auditVsPosition: Exclusion = {
  name: 'audit-exclusion',
  groups: [['settlement.auditSettlement'], ['settlement.positionFundsInOut', 'settlement.positionNDCEdit']],
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

const holding = (role: RoleDocument, resources: Record<string, string> = {}): Holding => ({ role, resources });

describe('separation of duties within a subject', () => {
  it('says nothing about either role on its own', () => {
    expect(broken([holding(roles['finance-manager']!)], [auditVsPosition], index)).toEqual([]);
    expect(broken([holding(roles.auditor!)], [auditVsPosition], index)).toEqual([]);
  });

  it('refuses the pair, naming the rule and both groups', () => {
    expect(broken([holding(roles['finance-manager']!), holding(roles.auditor!)], [auditVsPosition], index)).toEqual([
      'audit-exclusion: settlement.auditSettlement cannot be held with settlement.positionFundsInOut,settlement.positionNDCEdit',
    ]);
  });

  it('refuses a third group held beside either of the others', () => {
    const rule: Exclusion = {
      name: 'three-way',
      groups: [['settlement.positionFundsInOut'], ['settlement.positionNDCEdit'], ['settlement.auditSettlement']],
    };
    expect(broken([holding(roles.auditor!), holding({ grants: [{ permission: 'settlement.positionNDCEdit' }] })], [rule], index)).toHaveLength(1);
    expect(broken([holding({ grants: [{ permission: 'settlement.settlementView' }] })], [rule], index)).toEqual([]);
  });

  it('reports a role that carries both groups by itself', () => {
    const file: RolesFile = {
      roles: {
        ...roles,
        everything: {
          grants: [{ permission: 'settlement.auditSettlement' }, { permission: 'settlement.positionFundsInOut' }],
        },
      },
      exclusions: [auditVsPosition],
    };
    expect(validateExclusions(file, index)).toEqual([
      'role everything breaks audit-exclusion: settlement.auditSettlement cannot be held with settlement.positionFundsInOut',
    ]);
  });

  it('reports a seeded assignment that combines them', () => {
    const file: RolesFile = {
      roles,
      exclusions: [auditVsPosition],
      assignments: [
        { subject: 'alice', role: 'finance-manager' },
        { subject: 'alice', role: 'auditor' },
        { subject: 'bob', role: 'auditor' },
      ],
    };
    expect(validateExclusions(file, index)).toEqual([
      'alice breaks audit-exclusion: settlement.auditSettlement cannot be held with settlement.positionFundsInOut,settlement.positionNDCEdit',
    ]);
  });

  /** A rule naming a permission nothing advertises would never fire, which is worse than no rule. */
  it('refuses a rule that can never match', () => {
    expect(
      ruleProblems({ name: 'typo', groups: [['settlement.auditSettlment'], ['settlement.positionNDCEdit']] }, index),
    ).toEqual(['typo: unknown permission settlement.auditSettlment']);
  });

  it('refuses a rule with one group, or an empty one', () => {
    expect(ruleProblems({ name: 'half', groups: [['settlement.auditSettlement']] }, index)).toEqual([
      'half: needs two groups, each with a permission',
    ]);
    expect(ruleProblems({ name: 'hollow', groups: [['settlement.auditSettlement'], []] }, index)).toEqual([
      'hollow: needs two groups, each with a permission',
    ]);
  });

  it('checks only the permissions of composed services when told which are', () => {
    const rule: Exclusion = { name: 'later', groups: [['payouts.create'], ['settlement.auditSettlement']] };
    expect(ruleProblems(rule, index, new Set(['settlement']))).toEqual([]);
    expect(ruleProblems(rule, index)).toEqual(['later: unknown permission payouts.create']);
  });

  it('is silent when a deployment declares no rules', () => {
    expect(validateRoles({ roles, assignments: [{ subject: 'alice', role: 'auditor' }] }, index)).toEqual([]);
  });
});

describe('separation of duties within a resource', () => {
  const rule: Exclusion = {
    name: 'payout-per-dfsp',
    groups: [['settlement.createPayout'], ['settlement.approvePayout']],
    within: 'resource',
    resourceName: 'participant',
  };
  const maker = (over: string | string[] | undefined): RoleDocument => ({
    grants: [{ permission: 'settlement.createPayout', ...(over !== undefined ? { resources: { participant: over } } : {}) }],
  });
  const checker = (over: string | string[] | undefined): RoleDocument => ({
    grants: [{ permission: 'settlement.approvePayout', ...(over !== undefined ? { resources: { participant: over } } : {}) }],
  });

  it('allows both groups over different resources', () => {
    expect(broken([holding(maker('dfsp1')), holding(checker('dfsp2'))], [rule], index)).toEqual([]);
  });

  it('refuses both groups over one resource', () => {
    expect(broken([holding(maker('dfsp1')), holding(checker(['dfsp2', 'dfsp1']))], [rule], index)).toEqual([
      'payout-per-dfsp: settlement.createPayout cannot be held with settlement.approvePayout over one participant',
    ]);
  });

  it('counts every resource as overlapping a grant over all of them', () => {
    expect(broken([holding(maker('$all')), holding(checker('dfsp2'))], [rule], index)).toHaveLength(1);
  });

  it('reads a resource the role leaves open from the assignment that named it', () => {
    expect(
      broken([holding(maker(undefined), { participant: 'dfsp1' }), holding(checker(undefined), { participant: 'dfsp1' })], [rule], index),
    ).toHaveLength(1);
    expect(
      broken([holding(maker(undefined), { participant: 'dfsp1' }), holding(checker(undefined), { participant: 'dfsp2' })], [rule], index),
    ).toEqual([]);
  });

  it('refuses a rule over a permission its resource name does not scope', () => {
    expect(
      ruleProblems({ ...rule, groups: [['settlement.createPayout'], ['settlement.auditSettlement']] }, index),
    ).toEqual(['payout-per-dfsp: settlement.auditSettlement is not scoped by participant']);
  });
});
