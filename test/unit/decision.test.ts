import { parseScope } from '@mojaloop/authz/gateway';
import { ALL } from '@mojaloop/authz/reserved';
import { FastifyInstance } from 'fastify';

import { parsePayload } from '../../src/decision/payload';
import { buildServer } from '../../src/decision/server';
import { AUTHENTICATED, HELD_BY, MEMBERS, ROLE_NAMESPACE, Tuple } from '../../src/iam/materialize';
import { MemoryKeto } from './memory-keto';

const keto = new MemoryKeto();
const app = buildServer(keto);
const checks = vi.spyOn(keto, 'check');
const queries = vi.spyOn(keto, 'query');

const sent = async (method: 'GET' | 'POST', url: string, body?: unknown, server: FastifyInstance = app) => {
  const response = await server.inject({
    method,
    url,
    ...(body !== undefined ? { payload: JSON.stringify(body), headers: { 'content-type': 'application/json' } } : {}),
  });
  const scope = parseScope(response.headers as Record<string, string | undefined>);
  return {
    status: response.statusCode,
    scope: Object.fromEntries([...scope].map(([type, entry]) => [type, entry.all ? ALL : entry.ids])),
  };
};

/**
 * What the IAM writes into Keto: each grant to a role's members, the roles a
 * subject is a member of, and the roles every authenticated subject holds.
 */
const holding = (
  namespace: string,
  grants: Record<string, string[]>,
  members: Record<string, string[]> = {},
  everyone: string[] = [],
): void => {
  const membership = (role: string, subject: string): Tuple => ({
    namespace: ROLE_NAMESPACE,
    object: role,
    relation: MEMBERS,
    subject_id: subject,
  });
  keto.tuples = [
    ...Object.entries(grants).flatMap(([key, roles]) => {
      const [object, relation] = key.split('#') as [string, string];
      return roles.map((role) => ({
        namespace,
        object,
        relation,
        subject_set: { namespace: ROLE_NAMESPACE, object: role, relation: MEMBERS },
      }));
    }),
    ...Object.entries(members).flatMap(([subject, roles]) => roles.map((role) => membership(role, subject))),
    ...everyone.map((role) => ({ namespace: ROLE_NAMESPACE, object: role, relation: HELD_BY, subject_id: AUTHENTICATED })),
  ];
};

const post = (body: unknown) => sent('POST', '/', body);

describe('parsePayload', () => {
  const check = { namespace: 'mcm', object: 'dfsps/a', relation: 'updateDFSP', subject_id: 'u1' };

  it('reads a plain check', () => {
    expect(parsePayload(check)).toEqual({ checks: [check], scope: [] });
  });

  it('reads a scope pair `$resources` brought in', () => {
    const scope = [{ type: 'report', resourceName: 'report', followsAssignment: true }];
    expect(parsePayload({ ...check, scope })).toEqual({ checks: [check], scope });
  });

  it('reads allOf with a scope', () => {
    const scope = [
      { type: 'reports', resourceName: 'Report' },
      { type: 'dfsps', resourceName: 'Participant' },
    ];
    expect(parsePayload({ allOf: [check, check], scope })).toEqual({
      checks: [check, check],
      scope,
    });
  });

  it.each([
    ['a non-object', 'nope'],
    ['an unknown key', { ...check, tenant: 'x' }],
    ['a missing field', { namespace: 'mcm', object: 'dfsps/a', relation: 'updateDFSP' }],
    ['an empty subject', { ...check, subject_id: '' }],
    ['an empty allOf', { allOf: [] }],
    ['allOf beside a check', { allOf: [check], ...check }],
    ['a scope that is not an array', { ...check, scope: 'dfsps' }],
    ['a scope holding a bare string', { ...check, scope: ['dfsps'] }],
    ['a scope pair missing its resource name', { ...check, scope: [{ type: 'dfsps' }] }],
    ['a scope pair following its assignment by anything but true', { ...check, scope: [{ type: 'r', resourceName: 'r', followsAssignment: 'yes' }] }],
    [
      'a scope listing a type twice',
      {
        ...check,
        scope: [
          { type: 'dfsps', resourceName: 'Participant' },
          { type: 'dfsps', resourceName: 'Participant' },
        ],
      },
    ],
  ])('rejects %s', (_label, raw) => {
    expect(parsePayload(raw)).toBeUndefined();
  });
});

describe('decision endpoint', () => {
  beforeEach(() => {
    keto.tuples = [];
    checks.mockClear();
    queries.mockClear();
  });

  it('reports health without asking Keto', async () => {
    const response = await sent('GET', '/health');
    expect(response.status).toBe(200);
    expect(checks).not.toHaveBeenCalled();
    expect(queries).not.toHaveBeenCalled();
  });

  it('denies an unparseable payload without asking Keto', async () => {
    const response = await post({ namespace: 'mcm' });
    expect(response.status).toBe(403);
    expect(response.scope).toEqual({});
    expect(checks).not.toHaveBeenCalled();
    expect(queries).not.toHaveBeenCalled();
  });

  it('allows a check granted on the resource itself', async () => {
    holding('mcm', { 'dfsps/a#updateDFSP': ['operator'] }, { u1: ['operator'] });
    const response = await post({ namespace: 'mcm', object: 'dfsps/a', relation: 'updateDFSP', subject_id: 'u1' });
    expect(response.status).toBe(200);
    expect(response.scope).toEqual({});
  });

  it('allows a check granted on the type-wide object', async () => {
    holding('mcm', { 'dfsps/$all#updateDFSP': ['admin'] }, { u1: ['admin'] });
    const response = await post({ namespace: 'mcm', object: 'dfsps/a', relation: 'updateDFSP', subject_id: 'u1' });
    expect(response.status).toBe(200);
  });

  it('denies a check granted on a different resource', async () => {
    holding('mcm', { 'dfsps/b#updateDFSP': ['operator'] }, { u1: ['operator'] });
    const response = await post({ namespace: 'mcm', object: 'dfsps/a', relation: 'updateDFSP', subject_id: 'u1' });
    expect(response.status).toBe(403);
  });

  it('denies a grant held by a role the caller is not a member of', async () => {
    holding('mcm', { 'dfsps/a#updateDFSP': ['operator'] }, { u2: ['operator'] });
    const response = await post({ namespace: 'mcm', object: 'dfsps/a', relation: 'updateDFSP', subject_id: 'u1' });
    expect(response.status).toBe(403);
  });

  it('has no wider form for the service singleton', async () => {
    const response = await post({ namespace: 'mcm', object: '$self', relation: 'getDFSPs', subject_id: 'u1' });
    expect(response.status).toBe(403);
    expect(checks.mock.calls.map(([, object]) => object)).toEqual(['$self']);
  });

  it('allows what a role every authenticated subject holds grants, with no membership', async () => {
    holding('iam', { '$self#getChanges': ['signed-in'] }, {}, ['signed-in']);
    const response = await post({ namespace: 'iam', object: '$self', relation: 'getChanges', subject_id: 'anyone' });
    expect(response.status).toBe(200);
  });

  it('denies what no role grants even when roles every subject holds exist', async () => {
    holding('iam', { '$self#getChanges': ['signed-in'] }, {}, ['signed-in']);
    const response = await post({ namespace: 'iam', object: '$self', relation: 'createRole', subject_id: 'anyone' });
    expect(response.status).toBe(403);
  });

  it('scopes what a role every subject holds grants over', async () => {
    holding('ledger', { '$self#listThings': ['signed-in'], 'participant/p1#listThings': ['signed-in'] }, {}, ['signed-in']);
    const response = await post({
      namespace: 'ledger',
      object: '$self',
      relation: 'listThings',
      subject_id: 'anyone',
      scope: [{ type: 'participants', resourceName: 'participant' }],
    });
    expect(response.status).toBe(200);
    expect(response.scope).toEqual({ participants: ['p1'] });
  });

  it('allows allOf only when every check passes', async () => {
    const payload = (grants: Record<string, string[]>) => {
      holding('mcm', grants, { u1: ['linker'] });
      return post({
        allOf: [
          { namespace: 'mcm', object: 'reports/r1', relation: 'linkDfsp', subject_id: 'u1' },
          { namespace: 'mcm', object: 'dfsps/a', relation: 'linkDfsp', subject_id: 'u1' },
        ],
      });
    };
    expect((await payload({ 'dfsps/a#linkDfsp': ['linker'], 'reports/r1#linkDfsp': ['linker'] })).status).toBe(200);
    expect((await payload({ 'dfsps/a#linkDfsp': ['linker'] })).status).toBe(403);
  });

  it('delivers the rows the listing itself was granted over as the scope, spelled the service way', async () => {
    holding(
      'mcm',
      {
        '$self#getDFSPs': ['viewer'],
        'Participant/a#getDFSPs': ['viewer'],
        'Participant/b#getDFSPs': ['viewer'],
        'Participant/z#getDFSPs': ['someone-else'],
      },
      { u1: ['viewer'] },
    );
    const response = await post({
      namespace: 'mcm',
      object: '$self',
      relation: 'getDFSPs',
      subject_id: 'u1',
      scope: [{ type: 'dfsps', resourceName: 'Participant' }],
    });
    expect(response.status).toBe(200);
    expect(response.scope).toEqual({ dfsps: ['a', 'b'] });
  });

  it('lends a listing none of the resources the same role grants another operation over', async () => {
    holding(
      'mcm',
      { '$self#getDFSPs': ['observer'], 'Participant/a#getDFSPs': ['observer'], 'Participant/$all#getDfspJWSCerts': ['observer'] },
      { u1: ['observer'] },
    );
    const response = await post({
      namespace: 'mcm',
      object: '$self',
      relation: 'getDFSPs',
      subject_id: 'u1',
      scope: [{ type: 'dfsps', resourceName: 'Participant' }],
    });
    expect(response.scope).toEqual({ dfsps: ['a'] });
  });

  it('collapses a resource-name-wide grant to the every-resource scope', async () => {
    holding(
      'mcm',
      { '$self#getDFSPs': ['admin'], 'Participant/$all#getDFSPs': ['admin'], 'Participant/a#getDFSPs': ['admin'] },
      { u1: ['admin'] },
    );
    const response = await post({
      namespace: 'mcm',
      object: '$self',
      relation: 'getDFSPs',
      subject_id: 'u1',
      scope: [{ type: 'dfsps', resourceName: 'Participant' }],
    });
    expect(response.scope).toEqual({ dfsps: ALL });
  });

  it('denies a listing whose visible set is empty', async () => {
    holding('mcm', { '$self#getDFSPs': ['viewer'] }, { u1: ['viewer'] });
    const response = await post({
      namespace: 'mcm',
      object: '$self',
      relation: 'getDFSPs',
      subject_id: 'u1',
      scope: [{ type: 'dfsps', resourceName: 'Participant' }],
    });
    expect(response.status).toBe(403);
    expect(response.scope).toEqual({});
  });

  it('scopes a write by its own grant, so it knows its caller whatever else the role reaches', async () => {
    holding(
      'mcm',
      {
        '$self#postExternalCerts': ['dfsp-a-client'],
        'Participant/a#postExternalCerts': ['dfsp-a-client'],
        'Participant/$all#getDfspStatus': ['dfsp-a-client'],
      },
      { m1: ['dfsp-a-client'] },
    );
    const response = await post({
      namespace: 'mcm',
      object: '$self',
      relation: 'postExternalCerts',
      subject_id: 'm1',
      scope: [{ type: 'dfsps', resourceName: 'Participant' }],
    });
    expect(response.status).toBe(200);
    expect(response.scope).toEqual({ dfsps: ['a'] });
  });

  it('joins several declared types into one header', async () => {
    holding(
      'mcm',
      {
        '$self#getReportRows': ['auditor'],
        'Participant/a#getReportRows': ['auditor'],
        'Report/r1#getReportRows': ['auditor'],
        'Report/r2#getReport': ['auditor'],
      },
      { u1: ['auditor'] },
    );
    const response = await post({
      namespace: 'mcm',
      object: '$self',
      relation: 'getReportRows',
      subject_id: 'u1',
      scope: [
        { type: 'reports', resourceName: 'Report' },
        { type: 'dfsps', resourceName: 'Participant' },
      ],
    });
    expect(response.status).toBe(200);
    expect(response.scope).toEqual({ reports: ['r1'], dfsps: ['a'] });
  });

  it('denies when one declared type of several is empty', async () => {
    holding(
      'mcm',
      { '$self#getReportRows': ['auditor'], 'Report/r1#getReportRows': ['auditor'], 'Participant/a#updateDFSP': ['auditor'] },
      { u1: ['auditor'] },
    );
    const response = await post({
      namespace: 'mcm',
      object: '$self',
      relation: 'getReportRows',
      subject_id: 'u1',
      scope: [
        { type: 'reports', resourceName: 'Report' },
        { type: 'dfsps', resourceName: 'Participant' },
      ],
    });
    expect(response.status).toBe(403);
    expect(response.scope).toEqual({});
  });

  it('answers a name `$resources` brought in that the caller reaches none of as reaching none, and admits the request', async () => {
    holding('iam', { '$self#assignRole': ['dfsp-admin@participant=a'], 'participant/a#assignRole': ['dfsp-admin@participant=a'] }, {
      u1: ['dfsp-admin@participant=a'],
    });
    const response = await post({
      namespace: 'iam',
      object: '$self',
      relation: 'assignRole',
      subject_id: 'u1',
      scope: [
        { type: 'participant', resourceName: 'participant', followsAssignment: true },
        { type: 'report', resourceName: 'report', followsAssignment: true },
      ],
    });
    expect(response.status).toBe(200);
    expect(response.scope).toEqual({ participant: ['a'], report: [] });
  });

  /**
   * A role says what may be done and, for the same operation, over which
   * resources. Two roles are two such statements, so the resources of one must
   * not reach an operation only the other granted.
   */
  it('takes the scope from the roles that admitted the request', async () => {
    holding(
      'reports',
      {
        'Report/settlement#getReport': ['viewer@dfsp-a'],
        'Participant/dfsp-a#getReport': ['viewer@dfsp-a'],
        'Report/window#getReport': ['viewer@dfsp-b'],
        'Participant/dfsp-b#getReport': ['viewer@dfsp-b'],
      },
      { u1: ['viewer@dfsp-a', 'viewer@dfsp-b'] },
    );
    const run = (report: string) =>
      post({
        namespace: 'reports',
        object: `Report/${report}`,
        relation: 'getReport',
        subject_id: 'u1',
        scope: [
          { type: 'reports', resourceName: 'Report' },
          { type: 'participants', resourceName: 'Participant' },
        ],
      });

    const settlement = await run('settlement');
    expect(settlement.status).toBe(200);
    expect(settlement.scope).toEqual({ reports: ['settlement'], participants: ['dfsp-a'] });

    const window = await run('window');
    expect(window.status).toBe(200);
    expect(window.scope).toEqual({ reports: ['window'], participants: ['dfsp-b'] });

    const neither = await run('audit');
    expect(neither.status).toBe(403);
  });

  it('denies when Keto is unreachable', async () => {
    const unreachable = () => Promise.reject(new Error('connect ECONNREFUSED'));
    const cut = buildServer({ check: unreachable, query: unreachable });
    const response = await sent(
      'POST',
      '/',
      { namespace: 'mcm', object: 'dfsps/a', relation: 'updateDFSP', subject_id: 'u1' },
      cut,
    );
    expect(response.status).toBe(403);
    expect(response.scope).toEqual({});
  });
});
