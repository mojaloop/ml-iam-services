import { join } from 'node:path';

import { createGuard } from '@mojaloop/authz';
import { scopeHeaders } from '@mojaloop/authz/gateway';
import { ALL } from '@mojaloop/authz/reserved';
import { FastifyInstance } from 'fastify';

import {
  ApiState,
  CompositionSource,
  Controller,
  internalApi,
  People,
  publicApi,
  RoleStore,
} from '../../src/api/server';
import { CALLER_HEADER, emitCatalog, generate, loadSpec, ResourceNames } from '../../src/authzgen';
import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { Composition, controllerApi, serially } from '../../src/controller/api';
import { documentServer } from '../../src/http/backend';
import { Reason } from '../../src/iam/conditions';
import type { SessionPermissions } from '../../src/iam/kratos';
import { heldByMarker, parseInstance } from '../../src/iam/materialize';
import { Provisioner } from '../../src/iam/provisioner';
import type { Affected } from '../../src/iam/reconcile';
import { EXISTS, RESOURCE_NAMESPACE } from '../../src/iam/registry';
import { RoleView } from '../../src/iam/role-sync';
import { indexCatalogs, openResourceNames, RolesFile } from '../../src/iam/roles';
import { AuthzRole, MANAGED_BY } from '../../src/operator/cluster';
import { MemoryKeto } from './memory-keto';

const RN: Record<string, string> = { reports: 'report', participants: 'participant' };

const permission = (id: string, scopedBy: string[], bound: string[]): CatalogPermission => ({
  id,
  relation: id.split('.').slice(1).join('.'),
  operationId: id.split('.').slice(1).join('.'),
  summary: id,
  deprecated: false,
  method: 'GET',
  path: '/x',
  scopedBy,
  bound,
  resourceNames: Object.fromEntries(scopedBy.map((type) => [type, RN[type]!])),
});

const catalog: ServiceCatalog = {
  service: 'reports',
  namespace: 'reports',
  title: 'Reporting',
  basePath: '',
  resourceTypes: ['reports', 'participants'],
  permissions: [
    permission('reports.getReport', ['reports', 'participants'], ['reports']),
    permission('reports.moveFunds', [], []),
    permission('reports.auditFunds', [], []),
  ],
};
const index = indexCatalogs([catalog]);

const IAM = 'iam';
const PUBLIC_DOCUMENT = join(__dirname, '..', '..', 'src', 'api', 'public.yaml');

const names = {
  resourceNames: {
    report: { members: [{ service: 'reports', type: 'reports' }] },
    participant: { members: [{ service: 'reports', type: 'participants' }] },
    role: { members: [{ service: IAM, type: 'roles' }] },
    permission: { members: [{ service: IAM, type: 'permissions' }] },
  },
};

/** The IAM's own operations, composed against this deployment's resource names as the controller composes them. */
const iamCatalog = async (): Promise<ServiceCatalog> => emitCatalog(generate(await loadSpec(PUBLIC_DOCUMENT), IAM, {}, names).bundle);

const deployed = (): RolesFile => ({
  roles: {
    'report-viewer': { grants: [{ permission: 'reports.getReport' }] },
    'report-runner': { grants: [{ permission: 'reports.getReport', resources: { participant: '$all' } }] },
    'hub-operator': { grants: [{ permission: 'reports.getReport', resources: { report: '$all', participant: '$all' } }] },
    mover: { grants: [{ permission: 'reports.moveFunds' }] },
    checker: { grants: [{ permission: 'reports.auditFunds' }] },
  },
});

/** The same deployment, with one pair of duties it keeps in separate hands. */
const separated = (): RolesFile => ({
  ...deployed(),
  exclusions: [{ name: 'four-eyes', groups: [['reports.auditFunds'], ['reports.moveFunds']] }],
});

const viewsOf = (file: RolesFile): RoleView[] =>
  Object.entries(file.roles).map(([name, role]) => ({
    name,
    namespace: 'iam',
    labels: {},
    grants: role.grants,
    open: openResourceNames(role, index),
    ready: { reason: Reason.accepted, message: '' },
  }));

const people = (): People & { retired: string[]; written: Map<string, SessionPermissions> } => {
  const retired: string[] = [];
  const written = new Map<string, SessionPermissions>();
  return {
    retired,
    written,
    writePermissions: async (subject, permissions) => {
      written.set(subject, permissions);
    },
    subjects: async () => [{ id: 'alice', kind: 'person', email: 'alice@example.test' }],
    account: async (email) => ({ subject: `id-${email}`, created: true, invited: true }),
    deleteAccount: async (subject) => {
      retired.push(subject);
      return true;
    },
    createClient: async (request) => (request.id === 'taken' ? undefined : { subject: request.id ?? 'generated', secret: 's1' }),
    rotate: async (subject) => (subject === 'missing' ? undefined : { subject, secret: 's2' }),
    deleteClient: async (subject) => {
      retired.push(subject);
      return true;
    },
  };
};

const memoryRoles = (): RoleStore & { objects: Map<string, AuthzRole> } => {
  const objects = new Map<string, AuthzRole>();
  return {
    objects,
    get: async (name) => objects.get(name),
    create: async (role) => {
      if (objects.has(role.metadata!.name!)) {
        throw { status: 409, data: { message: `authzroles "${role.metadata!.name}" already exists` } };
      }
      objects.set(role.metadata!.name!, role);
    },
    apply: async (role) => {
      objects.set(role.metadata!.name!, role);
    },
    delete: async (name) => {
      objects.delete(name);
    },
  };
};

const setup = async (file: RolesFile = deployed(), applied = true, sources: { names: ResourceNames; fetch: typeof fetch } = { names, fetch }) => {
  const keto = new MemoryKeto(['Role', 'Resource', 'reports']);
  const provisioner = new Provisioner(keto, file, index, sources.names, sources.fetch);
  const catalogs = [catalog, await iamCatalog()];
  const composition: Composition = {
    catalog: catalogs,
    resourceNames: names.resourceNames,
    roles: viewsOf(file),
    separations: [],
    pending: [],
    renamed: { 'reports.getOldReport': 'reports.getReport' },
    removed: ['reports.purge'],
    servesAs: IAM,
  };
  const revoked: Affected[] = [];
  const controller = await controllerApi({
    keto,
    provisioner,
    exclusive: serially(),
    live: () => file,
    catalog: () => [catalog],
    composition: () => composition,
    etag: () => '"e1"',
    composed: () => undefined,
    applied: () => applied,
    ready: () => applied,
    leader: () => ({ self: true }),
    revoke: async (affected) => {
      revoked.push(affected);
    },
  });
  const toController: Controller = async (method, path, body, search) => {
    const response = await controller.inject({
      method,
      url: path,
      ...(search !== undefined ? { query: search } : {}),
      ...(body !== undefined ? { payload: body as object } : {}),
    });
    return { status: response.statusCode, body: response.json() };
  };
  const source: CompositionSource = {
    behind: false,
    etag: '"e1"',
    read: async () => undefined,
    now: () => composition,
    index: () => indexCatalogs(catalogs),
    onChange: () => () => undefined,
  };
  const identities = people();
  const store = memoryRoles();
  const state: ApiState = {
    namespace: 'iam',
    keto,
    composition: source,
    identities,
    roles: store,
    controller: toController,
  };
  const guard = await createGuard(PUBLIC_DOCUMENT);
  return {
    file,
    keto,
    provisioner,
    controller,
    identities,
    revoked,
    store,
    publicApp: await publicApi(state, guard),
    internal: await internalApi(state),
  };
};

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

const call = async (app: FastifyInstance, method: Method, url: string, body?: unknown, headers: Record<string, string> = {}) => {
  const response = await app.inject({
    method,
    url,
    headers: { ...headers, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
  });
  return {
    status: response.statusCode,
    headers: response.headers,
    body: response.body === '' ? undefined : response.json(),
  };
};

/** What the decision found the caller reaches, by type: every one, or these. */
type Reaches = Record<string, typeof ALL | string[]>;

/** The scope the gateway hands the IAM, as the decision found it. */
const scoped = (scope: Reaches = {}) =>
  scopeHeaders(
    new Map(Object.entries(scope).map(([type, set]) => [type, set === ALL ? { all: true, ids: [] } : { all: false, ids: set }])),
  );

/** A request as the gateway forwards it: the caller it authenticated and the scope the decision found. */
const as = (subject: string, scope: Reaches = {}) => ({ [CALLER_HEADER]: subject, ...scoped(scope) });

/** A scope reaching every resource of every name `$resources` brings into an IAM operation. */
const everything: Reaches = { report: ALL, participant: ALL, role: ALL, permission: ALL };

const provisioned = async (internal: FastifyInstance, resourceName: string, ...ids: string[]) => {
  for (const id of ids) expect((await call(internal, 'POST', '/provision', { resourceName, id })).status).toBe(200);
};

describe('what the role UI reads', () => {
  it('offers the permissions services advertise', async () => {
    const { publicApp } = await setup();
    const response = await call(publicApp, 'GET', '/catalog', undefined, as('admin'));
    expect(response.status).toBe(200);
    expect(response.body[0].permissions[0]).toMatchObject({
      id: 'reports.getReport',
      scopedBy: ['reports', 'participants'],
      bound: ['reports'],
    });
  });

  it('offers the roles, what each asks at assignment, and that the deployment owns them', async () => {
    const { publicApp } = await setup();
    const response = await call(publicApp, 'GET', '/roles', undefined, as('admin', { roles: ALL }));
    expect(response.body).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'report-viewer', open: ['participant', 'report'], owner: 'deployment' }),
        expect.objectContaining({ name: 'report-runner', open: ['report'] }),
        expect.objectContaining({ name: 'hub-operator', open: [] }),
      ]),
    );
  });

  it('shows only the roles the caller’s scope names', async () => {
    const { publicApp } = await setup();
    const response = await call(publicApp, 'GET', '/roles', undefined, as('dfsp-admin', { roles: ['report-viewer', 'mover'] }));
    expect(response.body.map((r: { name: string }) => r.name).sort()).toEqual(['mover', 'report-viewer']);
  });

  it('offers a resource nobody holds yet, recorded by the service that created it', async () => {
    const { publicApp, internal } = await setup();
    await provisioned(internal, 'report', 'dfspSettlement');
    await provisioned(internal, 'participant', 'dfsp-a');

    expect((await call(publicApp, 'GET', '/resources', undefined, as('admin', everything))).body).toEqual([
      { resourceName: 'participant', id: 'dfsp-a' },
      { resourceName: 'report', id: 'dfspSettlement' },
    ]);
    expect((await call(publicApp, 'GET', '/resources?resourceName=report', undefined, as('admin', everything))).body).toEqual([
      { resourceName: 'report', id: 'dfspSettlement' },
    ]);
  });

  it('lists only the resources the caller’s scope reaches', async () => {
    const { publicApp, internal } = await setup();
    await provisioned(internal, 'report', 'dfspSettlement');
    await provisioned(internal, 'participant', 'dfsp-a', 'dfsp-b');

    expect((await call(publicApp, 'GET', '/resources', undefined, as('dfsp-admin', { participant: ['dfsp-a'] }))).body).toEqual([
      { resourceName: 'participant', id: 'dfsp-a' },
    ]);
  });

  it('offers what a declared source lists now, as the controller reads it', async () => {
    const sourced: ResourceNames = {
      resourceNames: {
        ...names.resourceNames,
        participant: { ...names.resourceNames.participant, source: { url: 'http://ledger.test/participants', id: '/name' } },
      },
    };
    const ledger = (async () => Response.json([{ name: 'dfsp-x' }, { name: 'dfsp-y' }])) as unknown as typeof fetch;
    const { publicApp } = await setup(deployed(), true, { names: sourced, fetch: ledger });

    const listed = await call(publicApp, 'GET', '/resources?resourceName=participant', undefined, as('admin', everything));
    expect(listed.body).toEqual([
      { resourceName: 'participant', id: 'dfsp-x' },
      { resourceName: 'participant', id: 'dfsp-y' },
    ]);
    expect(listed.headers['stale-sources']).toBeUndefined();
  });

  it('names a source that did not answer, and offers what it listed last', async () => {
    const sourced: ResourceNames = {
      resourceNames: {
        ...names.resourceNames,
        participant: { ...names.resourceNames.participant, source: { url: 'http://ledger.test/participants', id: '/name' } },
      },
    };
    let up = true;
    const ledger = (async () => {
      if (!up) throw new TypeError('fetch failed');
      return Response.json([{ name: 'dfsp-x' }]);
    }) as unknown as typeof fetch;
    const { publicApp } = await setup(deployed(), true, { names: sourced, fetch: ledger });
    await call(publicApp, 'GET', '/resources?resourceName=participant', undefined, as('admin', everything));
    up = false;

    const listed = await call(publicApp, 'GET', '/resources?resourceName=participant', undefined, as('admin', everything));
    expect(listed.body).toEqual([{ resourceName: 'participant', id: 'dfsp-x' }]);
    expect(listed.headers['stale-sources']).toBe('participant');
  });

  it('refuses to record a resource under a name the deployment never declared', async () => {
    const { internal } = await setup();
    const response = await call(internal, 'POST', '/provision', { resourceName: 'widget', id: 'w1' });
    expect(response.status).toBe(422);
    expect(response.body.errors).toEqual(['no resource name called widget']);
  });

  it('forgets a resource that goes away', async () => {
    const { internal, keto } = await setup();
    await provisioned(internal, 'report', 'gone');
    expect((await call(internal, 'DELETE', '/provision', { resourceName: 'report', id: 'gone' })).body).toEqual({
      orphaned: [],
    });
    expect(keto.tuples.filter((t) => t.namespace === RESOURCE_NAMESPACE && t.relation === EXISTS)).toEqual([]);
  });

  it('shows the roles every signed-in subject holds among what one holds', async () => {
    const { publicApp, keto } = await setup();
    keto.tuples.push(heldByMarker('signed-in'));
    expect((await call(publicApp, 'GET', '/subjects/alice/assignments', undefined, as('admin'))).body).toEqual([
      { role: 'signed-in', resources: {}, through: 'authenticated' },
    ]);
  });
});

describe('a service assigning', () => {
  const assign = (internal: FastifyInstance, subject: string, body: unknown) =>
    call(internal, 'POST', `/subjects/${subject}/assignments`, body);

  it('writes the instance grants and the membership together', async () => {
    const { internal, keto } = await setup();
    await assign(internal, 'x', { role: 'hub-operator' });

    expect(keto.patches).toBe(1);
    expect(keto.tuples.map((t) => `${t.namespace}:${t.object}#${t.relation}`)).toEqual([
      'reports:report/$all#getReport',
      'reports:participant/$all#getReport',
      'Role:hub-operator#members',
    ]);
  });

  it('pairs each resource tuple on its own instance', async () => {
    const { internal, publicApp, keto } = await setup();
    await provisioned(internal, 'report', 'dfspSettlement', 'settlementWindow');
    await provisioned(internal, 'participant', 'dfsp-a', 'dfsp-b');

    const first = await assign(internal, 'alice', {
      role: 'report-viewer',
      resources: { report: 'dfspSettlement', participant: 'dfsp-a' },
    });
    expect(first.body).toEqual({ instance: 'report-viewer@participant=dfsp-a,report=dfspSettlement' });
    await assign(internal, 'alice', { role: 'report-viewer', resources: { report: 'settlementWindow', participant: 'dfsp-b' } });

    expect((await call(publicApp, 'GET', '/subjects/alice/assignments', undefined, as('admin'))).body).toEqual([
      { role: 'report-viewer', resources: { participant: 'dfsp-a', report: 'dfspSettlement' }, through: 'assigned' },
      { role: 'report-viewer', resources: { participant: 'dfsp-b', report: 'settlementWindow' }, through: 'assigned' },
    ]);
    const grants = keto.tuples.filter((t) => t.namespace === 'reports').map((t) => `${t.object}@${t.subject_set!.object}`);
    expect(grants).toEqual([
      'report/dfspSettlement@report-viewer@participant=dfsp-a,report=dfspSettlement',
      'participant/dfsp-a@report-viewer@participant=dfsp-a,report=dfspSettlement',
      'report/settlementWindow@report-viewer@participant=dfsp-b,report=settlementWindow',
      'participant/dfsp-b@report-viewer@participant=dfsp-b,report=settlementWindow',
    ]);
  });

  it('assigns a role over every resource of a name, present and future, as one instance', async () => {
    const { internal, keto } = await setup();
    await provisioned(internal, 'report', 'r1');
    const response = await assign(internal, 'alice', { role: 'report-viewer', resources: { report: 'r1', participant: '$all' } });
    expect(response.body).toEqual({ instance: 'report-viewer@participant=$all,report=r1' });
    expect(keto.tuples.some((t) => t.namespace === 'reports' && t.object === 'participant/$all')).toBe(true);
  });

  it('refuses an assignment naming a resource that does not exist', async () => {
    const { internal } = await setup();
    const response = await assign(internal, 'alice', { role: 'report-viewer', resources: { report: 'nope', participant: 'nobody' } });
    expect(response.status).toBe(422);
    expect(response.body.errors).toEqual(['no report called nope', 'no participant called nobody']);
  });

  it('refuses arguments that are not the ones the role takes', async () => {
    const { internal } = await setup();
    const response = await assign(internal, 'alice', { role: 'report-viewer', resources: { report: 'dfspSettlement' } });
    expect(response.status).toBe(422);
    expect(response.body.errors).toEqual(['role report-viewer takes [participant,report], got [report]']);
  });

  it('refuses a role nobody defined', async () => {
    const { internal } = await setup();
    expect((await assign(internal, 'alice', { role: 'invented' })).status).toBe(422);
  });

  it('refuses a body the document does not describe, saying what is wrong', async () => {
    const { internal } = await setup();
    const response = await assign(internal, 'alice', { resources: {} });
    expect(response.status).toBe(400);
    expect(response.body.errors.join(' ')).toContain('role');
  });

  it('takes a membership away and leaves the instance for whoever else holds it', async () => {
    const { internal, publicApp, keto } = await setup();
    await provisioned(internal, 'report', 'r1');
    await provisioned(internal, 'participant', 'p1');
    const resources = { report: 'r1', participant: 'p1' };
    await assign(internal, 'alice', { role: 'report-viewer', resources });
    await assign(internal, 'bob', { role: 'report-viewer', resources });

    await call(internal, 'DELETE', '/subjects/alice/assignments', { role: 'report-viewer', resources });

    expect((await call(publicApp, 'GET', '/subjects/alice/assignments', undefined, as('admin'))).body).toEqual([]);
    expect((await call(publicApp, 'GET', '/subjects/bob/assignments', undefined, as('admin'))).body).toHaveLength(1);
    expect(keto.tuples.some((t) => t.namespace === 'reports' && t.object === 'report/r1')).toBe(true);
  });

  it('still takes a membership away after the resource is gone', async () => {
    const { internal } = await setup();
    await provisioned(internal, 'report', 'r1');
    await provisioned(internal, 'participant', 'p1');
    const resources = { report: 'r1', participant: 'p1' };
    await assign(internal, 'alice', { role: 'report-viewer', resources });
    await call(internal, 'DELETE', '/provision', { resourceName: 'report', id: 'r1' });

    expect((await call(internal, 'DELETE', '/subjects/alice/assignments', { role: 'report-viewer', resources })).status).toBe(200);
  });

  /**
   * Neither grant is wrong on its own, and they arrive months and two admins
   * apart. The write is the only moment anything sees both.
   */
  it('refuses the second role when a rule keeps the two apart', async () => {
    const { internal, publicApp } = await setup(separated());
    expect((await assign(internal, 'alice', { role: 'mover' })).status).toBe(200);

    const second = await assign(internal, 'alice', { role: 'checker' });
    expect(second.status).toBe(422);
    expect(second.body.errors).toEqual(['four-eyes: reports.auditFunds cannot be held with reports.moveFunds']);

    expect((await assign(internal, 'bob', { role: 'checker' })).status).toBe(200);
    expect((await call(publicApp, 'GET', '/subjects/alice/assignments', undefined, as('admin'))).body).toEqual([
      { role: 'mover', resources: {}, through: 'assigned' },
    ]);
  });

  it('counts a role that waits for its service, which its members hold again once the service is back', async () => {
    const { internal, provisioner, file } = await setup(separated());
    expect((await assign(internal, 'alice', { role: 'mover' })).status).toBe(200);
    const { mover, ...others } = file.roles;
    provisioner.use({ ...file, roles: others }, index, { mover: mover! });

    const second = await assign(internal, 'alice', { role: 'checker' });
    expect(second.status).toBe(422);
    expect(second.body.errors).toEqual(['four-eyes: reports.auditFunds cannot be held with reports.moveFunds']);
  });

  it('judges two assignments arriving together one after the other', async () => {
    const { controller, keto } = await setup(separated());
    keto.yielding = true;
    const answers = await Promise.all(
      ['mover', 'checker'].map((role) =>
        controller.inject({ method: 'POST', url: '/assignments', payload: { subject: 'alice', role } }),
      ),
    );
    expect(answers.map((a) => a.statusCode).sort()).toEqual([200, 422]);
  });

  it('lets the first role go so the other can be given', async () => {
    const { internal } = await setup(separated());
    await assign(internal, 'alice', { role: 'mover' });
    await call(internal, 'DELETE', '/subjects/alice/assignments', { role: 'mover' });
    expect((await assign(internal, 'alice', { role: 'checker' })).status).toBe(200);
  });

  it('reads an instance object back into the choice that made it', () => {
    expect(parseInstance('report-viewer@participant=dfsp-a,report=dfspSettlement')).toEqual({
      role: 'report-viewer',
      resources: { participant: 'dfsp-a', report: 'dfspSettlement' },
    });
    expect(parseInstance('hub-operator')).toEqual({ role: 'hub-operator', resources: {} });
  });
});

/** An admin holding everything, and carol holding the viewer role over one report and one participant. */
const staffed = async (file: RolesFile = deployed()) => {
  const world = await setup(file);
  await provisioned(world.internal, 'report', 'r1', 'r2');
  await provisioned(world.internal, 'participant', 'p1', 'p2');
  await call(world.internal, 'POST', '/subjects/admin/assignments', { role: 'hub-operator' });
  await call(world.internal, 'POST', '/subjects/carol/assignments', {
    role: 'report-viewer',
    resources: { report: 'r1', participant: 'p1' },
  });
  return world;
};

describe('handing out a role through the gateway', () => {
  const hand = (app: FastifyInstance, by: string, scope: Reaches, resources: Record<string, string>) =>
    call(app, 'POST', '/subjects/alice/assignments', { role: 'report-viewer', resources }, as(by, scope));

  it('refuses whoever holds everything the role gives when their scope does not name it', async () => {
    const { publicApp } = await staffed();
    const response = await hand(publicApp, 'admin', { roles: [] }, { report: 'r2', participant: 'p2' });
    expect(response.status).toBe(422);
    expect(response.body.errors).toEqual(['your scope does not name report-viewer']);
  });

  it('lets a scope naming the role hand it out over what its holder holds, past what the scope reaches', async () => {
    const { publicApp } = await staffed();
    expect((await hand(publicApp, 'carol', { roles: ['report-viewer'] }, { report: 'r1', participant: 'p1' })).status).toBe(200);
  });

  it('refuses a holder handing it out over a resource they neither hold nor reach, saying what they lack', async () => {
    const { publicApp } = await staffed();
    const response = await hand(publicApp, 'carol', { roles: ['report-viewer'] }, { report: 'r1', participant: 'p2' });
    expect(response.status).toBe(422);
    expect(response.body.errors).toEqual([
      'report-viewer gives reports.getReport over report=r1 and participant=p2, which you do not hold, and your scope does not reach over report=r1 and participant=p2',
    ]);
  });

  it('lets a scope naming the role hand it out over what the scope reaches, whatever it gives', async () => {
    const { publicApp } = await staffed();
    const scope = { roles: ['report-viewer'], report: ALL, participant: ['p2'] };
    expect((await hand(publicApp, 'carol', scope, { report: 'r2', participant: 'p2' })).status).toBe(200);
  });

  it('refuses a scope naming the role over a resource the scope does not reach', async () => {
    const { publicApp } = await staffed();
    const scope = { roles: ['report-viewer'], report: ALL, participant: ['p1'] };
    const response = await hand(publicApp, 'carol', scope, { report: 'r2', participant: 'p2' });
    expect(response.status).toBe(422);
    expect(response.body.errors).toEqual([
      'report-viewer gives reports.getReport over report=r2 and participant=p2, which you do not hold, and your scope does not reach over participant=p2',
    ]);
  });

  it('hands a role out over every resource of a name only to a scope reaching every one', async () => {
    const { publicApp } = await staffed();
    const every = { report: 'r1', participant: '$all' };
    expect((await hand(publicApp, 'carol', { roles: ['report-viewer'], report: ALL, participant: ['p1', 'p2'] }, every)).status).toBe(422);
    expect((await hand(publicApp, 'carol', { roles: ['report-viewer'], report: ALL, participant: ALL }, every)).status).toBe(200);
  });

  it('does not add two holdings over different halves into one', async () => {
    const { publicApp, internal } = await staffed();
    await call(internal, 'POST', '/subjects/carol/assignments', {
      role: 'report-viewer',
      resources: { report: 'r2', participant: 'p2' },
    });
    expect((await hand(publicApp, 'carol', { roles: ['report-viewer'] }, { report: 'r1', participant: 'p2' })).status).toBe(422);
  });

  it('refuses a request the gateway named no caller for', async () => {
    const { publicApp } = await staffed();
    const response = await call(publicApp, 'POST', '/subjects/alice/assignments', { role: 'mover' }, scoped({ roles: ALL }));
    expect(response.status).toBe(401);
    const empty = await call(publicApp, 'POST', '/subjects/alice/assignments', { role: 'mover' }, { [CALLER_HEADER]: '', ...scoped({ roles: ALL }) });
    expect(empty.status).toBe(401);
  });
});

describe('writing a role through the gateway', () => {
  const create = (app: FastifyInstance, by: string, scope: Reaches, resources?: Record<string, string>) =>
    call(
      app,
      'POST',
      '/roles',
      { name: 'composed', grants: [{ permission: 'reports.getReport', ...(resources !== undefined ? { resources } : {}) }] },
      as(by, scope),
    );

  it('writes a role of grants the writer holds, as the IAM own object', async () => {
    const { publicApp, store } = await staffed();
    const response = await create(publicApp, 'admin', { permissions: [] }, { report: '$all' });
    expect(response.status).toBe(201);
    expect(response.body).toMatchObject({ name: 'composed', open: ['participant'], owner: 'iam' });
    expect(store.objects.get('composed')!.metadata).toMatchObject({ namespace: 'iam', labels: MANAGED_BY });
  });

  it('lets a holder write a grant over everything they hold every one of', async () => {
    const { publicApp } = await staffed();
    expect((await create(publicApp, 'admin', { permissions: [] }, { report: '$all', participant: '$all' })).status).toBe(201);
  });

  it('refuses a holder a grant wider than what they hold', async () => {
    const { publicApp } = await staffed();
    const wider = await create(publicApp, 'carol', { permissions: [] }, { report: '$all' });
    expect(wider.status).toBe(422);
    expect(wider.body.errors).toEqual(['you do not hold reports.getReport over report=$all, and your scope does not name it']);
  });

  it('passes a resource name left to the assignment, which reaches nothing until an assignment names it', async () => {
    const { publicApp } = await staffed();
    expect((await create(publicApp, 'carol', { permissions: [] })).status).toBe(201);
  });

  it('refuses a writer who holds the permission nowhere and whose scope does not name it', async () => {
    const { publicApp } = await staffed();
    const response = await create(publicApp, 'dave', { permissions: [] });
    expect(response.status).toBe(422);
    expect(response.body.errors).toEqual(['you do not hold reports.getReport, and your scope does not name it']);
  });

  it('lets a scope naming the permission write it without holding it, no wider than the scope reaches', async () => {
    const { publicApp } = await staffed();
    const reaching = { permissions: ['reports.getReport'], participant: ALL };
    expect((await create(publicApp, 'dave', reaching, { participant: '$all' })).status).toBe(201);
  });

  it('refuses a scope naming the permission a reach it does not have', async () => {
    const { publicApp } = await staffed();
    const response = await create(publicApp, 'dave', { permissions: ['reports.getReport'], participant: ['p1'] }, { participant: '$all' });
    expect(response.status).toBe(422);
    expect(response.body.errors).toEqual(['your scope names reports.getReport, and does not reach over participant=$all']);
  });

  it('refuses a name already taken', async () => {
    const { publicApp } = await staffed();
    expect((await create(publicApp, 'admin', { permissions: ALL })).status).toBe(201);
    expect((await create(publicApp, 'admin', { permissions: ALL })).status).toBe(409);
  });

  it('leaves a role the deployment applied to the deployment, and finds no role that does not exist', async () => {
    const { publicApp } = await staffed();
    const change = { grants: [{ permission: 'reports.moveFunds' }] };
    const admin = as('admin', { roles: ALL, permissions: ALL });
    expect((await call(publicApp, 'PUT', '/roles/report-viewer', change, admin)).status).toBe(409);
    expect((await call(publicApp, 'PUT', '/roles/nothing', change, admin)).status).toBe(404);
  });

  it('deletes a role of its own only once nobody holds it', async () => {
    const { publicApp, internal, store, file } = await staffed();
    await create(publicApp, 'admin', { permissions: ALL }, { report: '$all', participant: '$all' });
    file.roles['composed'] = { grants: [{ permission: 'reports.getReport', resources: { report: '$all', participant: '$all' } }] };

    await call(internal, 'POST', '/subjects/alice/assignments', { role: 'composed' });
    expect((await call(publicApp, 'DELETE', '/roles/composed', undefined, as('admin', { roles: ALL }))).status).toBe(409);
    await call(internal, 'DELETE', '/subjects/alice/assignments', { role: 'composed' });
    expect((await call(publicApp, 'DELETE', '/roles/composed', undefined, as('admin', { roles: ALL }))).status).toBe(204);
    expect(store.objects.has('composed')).toBe(false);
  });

  it('keeps a role of its own while another role names it by id', async () => {
    const naming = { grants: [{ permission: 'iam.assignRole', resources: { role: ['composed'] } }] };
    const { publicApp, store } = await staffed({ ...deployed(), roles: { ...deployed().roles, 'composed-admin': naming } });
    await create(publicApp, 'admin', { permissions: ALL }, { report: '$all', participant: '$all' });

    const response = await call(publicApp, 'DELETE', '/roles/composed', undefined, as('admin', { roles: ALL }));
    expect(response.status).toBe(409);
    expect(response.body.errors).toEqual(['composed is named by the grants of composed-admin; take it out of them first']);
    expect(store.objects.has('composed')).toBe(true);
  });
});

describe('permissions in the session', () => {
  it('writes what a person who signs in holds, over the resources they hold it on', async () => {
    const { internal, identities } = await staffed();
    expect((await call(internal, 'POST', '/login', { identity_id: 'carol' })).status).toBe(204);
    expect((await call(internal, 'POST', '/login', { identity_id: 'admin' })).status).toBe(204);

    expect(identities.written.get('carol')).toMatchObject({ 'reports.getReport': { report: ['r1'], participant: ['p1'] } });
    expect(identities.written.get('carol')).not.toHaveProperty(['reports.moveFunds']);
    expect(identities.written.get('admin')).toMatchObject({ 'reports.getReport': { report: '$all', participant: '$all' } });
  });

  it('ends the session of the subject a role is given to or taken from, and of nobody when it is refused', async () => {
    const world = await staffed();
    world.revoked.length = 0;
    expect((await call(world.internal, 'POST', '/subjects/alice/assignments', { role: 'mover' })).status).toBe(200);
    expect((await call(world.internal, 'DELETE', '/subjects/alice/assignments', { role: 'mover' })).status).toBe(200);
    expect((await call(world.internal, 'POST', '/subjects/alice/assignments', { role: 'nowhere' })).status).toBe(422);
    expect(world.revoked).toEqual([
      { everyone: false, subjects: ['alice'] },
      { everyone: false, subjects: ['alice'] },
    ]);
  });

  it('ends the sessions of everyone who held a role over a resource it retires, whatever else they still hold', async () => {
    const world = await staffed();
    await call(world.internal, 'POST', '/subjects/carol/assignments', { role: 'mover' });
    world.revoked.length = 0;
    expect((await call(world.internal, 'DELETE', '/provision', { resourceName: 'participant', id: 'p1' })).status).toBe(200);
    expect(world.revoked).toEqual([{ everyone: false, subjects: ['carol'] }]);
  });
});

describe('people and machine clients', () => {
  it('retires a person only once they hold no role', async () => {
    const { internal, identities } = await setup();
    await call(internal, 'POST', '/subjects/alice/assignments', { role: 'mover' });
    expect((await call(internal, 'DELETE', '/accounts/alice')).status).toBe(409);
    expect((await call(internal, 'DELETE', '/accounts/bob')).status).toBe(204);
    expect(identities.retired).toEqual(['bob']);
  });

  it('answers a new client its secret once, and refuses an id already taken', async () => {
    const { internal } = await setup();
    expect(await call(internal, 'POST', '/clients', { id: 'dfsp1' })).toMatchObject({
      status: 201,
      body: { subject: 'dfsp1', secret: 's1' },
    });
    expect((await call(internal, 'POST', '/clients', { id: 'taken' })).status).toBe(409);
  });

  it('rotates a client secret, and says when there is no such client', async () => {
    const { internal } = await setup();
    expect((await call(internal, 'POST', '/clients/dfsp1/secret')).body).toEqual({ subject: 'dfsp1', secret: 's2' });
    expect((await call(internal, 'POST', '/clients/missing/secret')).status).toBe(404);
  });
});

describe('the state the IAM reports', () => {
  it('says which permissions services renamed and removed', async () => {
    const { publicApp } = await setup();
    const state = await call(publicApp, 'GET', '/state', undefined, as('admin'));
    expect(state.body).toMatchObject({ renamed: { 'reports.getOldReport': 'reports.getReport' }, removed: ['reports.purge'] });
  });
});

describe('a controller still starting', () => {
  it('is alive, says it is not ready, and takes no write', async () => {
    const { controller } = await setup(deployed(), false);
    expect((await controller.inject({ method: 'GET', url: '/health' })).statusCode).toBe(200);
    expect((await controller.inject({ method: 'GET', url: '/ready' })).statusCode).toBe(503);
    const write = await controller.inject({ method: 'POST', url: '/assignments', payload: { subject: 'alice', role: 'mover' } });
    expect(write.statusCode).toBe(503);
    expect((await controller.inject({ method: 'GET', url: '/composition' })).statusCode).toBe(503);
  });
});

describe('the composition the controller serves', () => {
  it('answers its ETag, and nothing more to a reader that already holds it', async () => {
    const { controller } = await setup();
    const first = await controller.inject({ method: 'GET', url: '/composition' });
    expect(first.headers['etag']).toBe('"e1"');
    const again = await controller.inject({ method: 'GET', url: '/composition', headers: { 'if-none-match': '"e1"' } });
    expect(again.statusCode).toBe(304);
  });
});

describe('a server routing by its document', () => {
  const definition = (paths: Record<string, unknown>) => ({ openapi: '3.1.0', info: { title: 'IAM', version: '1' }, paths });
  const operation = (operationId: string) => ({ get: { operationId, responses: { 200: { description: 'ok' } } } });

  it('refuses to start on an operation with no handler', async () => {
    await expect(
      documentServer(definition({ '/health': operation('getHealth'), '/surprise': operation('getSurprise') }), {
        getHealth: () => ({ status: 200 }),
      }),
    ).rejects.toThrow(/no handler for getSurprise/);
  });

  it('refuses to start on a handler with no operation', async () => {
    await expect(
      documentServer(definition({ '/health': operation('getHealth') }), {
        getHealth: () => ({ status: 200 }),
        getCatalog: () => ({ status: 200 }),
      }),
    ).rejects.toThrow(/no operation for \[getCatalog\]/);
  });

  it('answers an unknown path 404 with the reason', async () => {
    const app = await documentServer(definition({ '/health': operation('getHealth') }), {
      getHealth: () => ({ status: 200 }),
    });
    expect((await call(app, 'GET', '/nowhere')).body).toEqual({ errors: ['Not found'] });
  });
});
