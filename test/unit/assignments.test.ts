import { createServer } from 'node:http';

import request from 'supertest';

import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { KetoWriter } from '../../src/iam/keto';
import { Tuple } from '../../src/iam/materialize';
import { parseInstance, Provisioner } from '../../src/iam/provisioner';
import { EXISTS, RESOURCE_NAMESPACE } from '../../src/iam/registry';
import { indexCatalogs, RolesFile } from '../../src/iam/roles';
import { buildHandler } from '../../src/iam/server';

/** A Keto that keeps tuples in memory and answers the filters the IAM uses. */
class MemoryKeto extends KetoWriter {
  public tuples: Tuple[] = [];

  constructor() {
    super('http://keto-write-test', 'http://keto-read-test');
  }

  override async query(params: Record<string, string>): Promise<Tuple[]> {
    return this.tuples.filter((t) =>
      Object.entries(params).every(([key, value]) => {
        if (key === 'subject_set.namespace') return t.subject_set?.namespace === value;
        if (key === 'subject_set.object') return t.subject_set?.object === value;
        if (key === 'subject_set.relation') return t.subject_set?.relation === value;
        return (t as unknown as Record<string, unknown>)[key] === value;
      }),
    );
  }

  override async put(tuple: Tuple): Promise<void> {
    await this.deleteWhere({
      namespace: tuple.namespace,
      object: tuple.object,
      relation: tuple.relation,
      ...(tuple.subject_id !== undefined
        ? { subject_id: tuple.subject_id }
        : {
          'subject_set.namespace': tuple.subject_set!.namespace,
          'subject_set.object': tuple.subject_set!.object,
          'subject_set.relation': tuple.subject_set!.relation,
        }),
    });
    this.tuples.push(tuple);
  }

  override async deleteWhere(params: Record<string, string>): Promise<void> {
    const doomed = await this.query(params);
    this.tuples = this.tuples.filter((t) => !doomed.includes(t));
  }
}

const RN: Record<string, string> = { reports: 'Report', participants: 'Participant' };

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
  title: 'Reporting',
  basePath: '',
  resourceTypes: ['reports', 'participants'],
  permissions: [
    permission('reports.getReport', ['reports', 'participants'], ['reports']),
    permission('reports.moveFunds', [], []),
    permission('reports.auditFunds', [], []),
  ],
};

const names = {
  resourceNames: {
    Report: { members: [{ service: 'reports', type: 'reports' }] },
    Participant: { members: [{ service: 'reports', type: 'participants' }] },
  },
};

const roles: RolesFile = {
  roles: {
    'report-viewer': {
      grants: [{ permission: 'reports.getReport' }],
    },
    'report-runner': {
      grants: [{ permission: 'reports.getReport', resources: { Participant: 'all' } }],
    },
    'hub-operator': {
      grants: [{ permission: 'reports.getReport', resources: { Report: 'all', Participant: 'all' } }],
    },
  },
};

/** The same deployment, with one pair of duties it keeps in separate hands. */
const separated: RolesFile = {
  roles: {
    mover: { grants: [{ permission: 'reports.moveFunds' }] },
    checker: { grants: [{ permission: 'reports.auditFunds' }] },
  },
  exclusions: [{ name: 'four-eyes', a: ['reports.auditFunds'], b: ['reports.moveFunds'] }],
};

const setup = async () => {
  const keto = new MemoryKeto();
  const provisioner = new Provisioner(keto, roles, indexCatalogs([catalog]), names);
  const handler = await buildHandler(provisioner, { catalog: [catalog], roles, names });
  const app = createServer((req, res) => {
    handler(req, res).catch(() => res.writeHead(500).end());
  });
  return { keto, provisioner, app };
};

describe('what the role UI reads', () => {
  it('offers the permissions services advertise', async () => {
    const { app } = await setup();
    const response = await request(app).get('/catalog');
    expect(response.status).toBe(200);
    expect(response.body[0].permissions[0]).toMatchObject({
      id: 'reports.getReport',
      scopedBy: ['reports', 'participants'],
      bound: ['reports'],
    });
  });

  it('offers the roles, and what each one asks at assignment', async () => {
    const { app } = await setup();
    const response = await request(app).get('/roles');
    expect(response.body).toEqual([
      expect.objectContaining({ name: 'report-viewer', open: ['Participant', 'Report'] }),
      expect.objectContaining({ name: 'report-runner', open: ['Report'] }),
      expect.objectContaining({ name: 'hub-operator', open: [] }),
    ]);
  });

  /**
   * A report is grantable the day it is applied, so it has to be offered
   * before anybody holds it.
   */
  it('offers a resource nobody holds yet', async () => {
    const { provisioner, app } = await setup();
    await provisioner.provision({ resourceName: 'Report', id: 'dfspSettlement' });
    await provisioner.provision({ resourceName: 'Participant', id: 'dfsp-a' });

    expect((await request(app).get('/resources')).body).toEqual([
      { resourceName: 'Participant', id: 'dfsp-a' },
      { resourceName: 'Report', id: 'dfspSettlement' },
    ]);
    expect((await request(app).get('/resources?resourceName=Report')).body).toEqual([
      { resourceName: 'Report', id: 'dfspSettlement' },
    ]);
  });

  it('forgets a resource that goes away', async () => {
    const { provisioner, keto } = await setup();
    await provisioner.provision({ resourceName: 'Report', id: 'gone' });
    await provisioner.deprovision({ resourceName: 'Report', id: 'gone' });
    expect(keto.tuples.filter((t) => t.namespace === RESOURCE_NAMESPACE && t.relation === EXISTS)).toEqual([]);
  });
});

describe('assigning', () => {
  const assign = (app: ReturnType<typeof setup>['app'], body: unknown) =>
    request(app).post('/subjects/alice/assignments').send(body as object);

  it('writes the instance grants and the membership together', async () => {
    const { app, keto } = await setup();
    const { provisioner } = await setup();
    void provisioner;
    await request(app).post('/subjects/x/assignments').send({ role: 'hub-operator' });

    expect(keto.tuples.map((t) => `${t.namespace}:${t.object}#${t.relation}`)).toEqual([
      'reports:Report/__all__#getReport',
      'reports:Participant/__all__#getReport',
      'Role:hub-operator#members',
    ]);
  });

  it('pairs each resource tuple on its own instance', async () => {
    const { app, provisioner, keto } = await setup();
    for (const id of ['dfspSettlement', 'settlementWindow']) {
      await provisioner.provision({ resourceName: 'Report', id });
    }
    for (const id of ['dfsp-a', 'dfsp-b']) {
      await provisioner.provision({ resourceName: 'Participant', id });
    }

    expect(
      (await assign(app, { role: 'report-viewer', resources: { Report: 'dfspSettlement', Participant: 'dfsp-a' } }))
        .body,
    ).toEqual({ instance: 'report-viewer@Participant=dfsp-a,Report=dfspSettlement' });
    await assign(app, { role: 'report-viewer', resources: { Report: 'settlementWindow', Participant: 'dfsp-b' } });

    const held = await request(app).get('/subjects/alice/assignments');
    expect(held.body).toEqual([
      { role: 'report-viewer', resources: { Participant: 'dfsp-a', Report: 'dfspSettlement' } },
      { role: 'report-viewer', resources: { Participant: 'dfsp-b', Report: 'settlementWindow' } },
    ]);

    const grants = keto.tuples.filter((t) => t.namespace === 'reports').map((t) => `${t.object}@${t.subject_set!.object}`);
    expect(grants).toEqual([
      'Report/dfspSettlement@report-viewer@Participant=dfsp-a,Report=dfspSettlement',
      'Participant/dfsp-a@report-viewer@Participant=dfsp-a,Report=dfspSettlement',
      'Report/settlementWindow@report-viewer@Participant=dfsp-b,Report=settlementWindow',
      'Participant/dfsp-b@report-viewer@Participant=dfsp-b,Report=settlementWindow',
    ]);
  });

  it('refuses to record a resource under a name the deployment never declared', async () => {
    const { provisioner } = await setup();
    expect(await provisioner.provision({ resourceName: 'Widget', id: 'w1' })).toEqual({
      problem: 'no resource name called Widget',
    });
  });

  it('refuses an assignment naming a resource that does not exist', async () => {
    const { app } = await setup();
    const response = await assign(app, { role: 'report-viewer', resources: { Report: 'nope', Participant: 'nobody' } });
    expect(response.status).toBe(422);
    expect(response.body.errors).toEqual(['no Report called nope', 'no Participant called nobody']);
  });

  it('refuses arguments that are not the ones the role takes', async () => {
    const { app } = await setup();
    const response = await assign(app, { role: 'report-viewer', resources: { Report: 'dfspSettlement' } });
    expect(response.status).toBe(422);
    expect(response.body.errors).toEqual(['role report-viewer takes [Participant,Report], got [Report]']);
  });

  it('refuses a role nobody defined', async () => {
    const { app } = await setup();
    expect((await assign(app, { role: 'invented' })).status).toBe(422);
  });

  it('takes a membership away and leaves the instance for whoever else holds it', async () => {
    const { app, provisioner, keto } = await setup();
    await provisioner.provision({ resourceName: 'Report', id: 'r1' });
    await provisioner.provision({ resourceName: 'Participant', id: 'p1' });
    const resources = { Report: 'r1', Participant: 'p1' };
    await assign(app, { role: 'report-viewer', resources });
    await request(app).post('/subjects/bob/assignments').send({ role: 'report-viewer', resources });

    await request(app).delete('/subjects/alice/assignments').send({ role: 'report-viewer', resources });

    expect((await request(app).get('/subjects/alice/assignments')).body).toEqual([]);
    expect((await request(app).get('/subjects/bob/assignments')).body).toHaveLength(1);
    expect(keto.tuples.some((t) => t.namespace === 'reports' && t.object === 'Report/r1')).toBe(true);
  });

  it('still takes a membership away after the resource is gone', async () => {
    const { app, provisioner } = await setup();
    await provisioner.provision({ resourceName: 'Report', id: 'r1' });
    await provisioner.provision({ resourceName: 'Participant', id: 'p1' });
    const resources = { Report: 'r1', Participant: 'p1' };
    await assign(app, { role: 'report-viewer', resources });
    await provisioner.deprovision({ resourceName: 'Report', id: 'r1' });

    const response = await request(app)
      .delete('/subjects/alice/assignments')
      .send({ role: 'report-viewer', resources });
    expect(response.status).toBe(200);
    expect((await request(app).get('/subjects/alice/assignments')).body).toEqual([]);
  });

  /**
   * Neither grant is wrong on its own, and they arrive months and two admins
   * apart. The write is the only moment anything sees both.
   */
  it('refuses the second role when a rule keeps the two apart', async () => {
    const keto = new MemoryKeto();
    const provisioner = new Provisioner(keto, separated, indexCatalogs([catalog]));
    const handler = await buildHandler(provisioner, { catalog: [catalog], roles: separated });
    const app = createServer((req, res) => {
      handler(req, res).catch(() => res.writeHead(500).end());
    });

    expect((await request(app).post('/subjects/alice/assignments').send({ role: 'mover' })).status).toBe(200);

    const second = await request(app).post('/subjects/alice/assignments').send({ role: 'checker' });
    expect(second.status).toBe(422);
    expect(second.body.errors).toEqual([
      'four-eyes: reports.auditFunds cannot be held with reports.moveFunds',
    ]);

    // Somebody else may hold either, and alice keeps the one she had
    expect((await request(app).post('/subjects/bob/assignments').send({ role: 'checker' })).status).toBe(200);
    expect((await request(app).get('/subjects/alice/assignments')).body).toEqual([{ role: 'mover', resources: {} }]);
  });

  it('lets the first role go so the other can be given', async () => {
    const keto = new MemoryKeto();
    const provisioner = new Provisioner(keto, separated, indexCatalogs([catalog]));
    const handler = await buildHandler(provisioner, { catalog: [catalog], roles: separated });
    const app = createServer((req, res) => {
      handler(req, res).catch(() => res.writeHead(500).end());
    });

    await request(app).post('/subjects/alice/assignments').send({ role: 'mover' });
    await request(app).delete('/subjects/alice/assignments').send({ role: 'mover' });
    expect((await request(app).post('/subjects/alice/assignments').send({ role: 'checker' })).status).toBe(200);
  });

  it('reads an instance object back into the choice that made it', () => {
    expect(parseInstance('report-viewer@Participant=dfsp-a,Report=dfspSettlement')).toEqual({
      role: 'report-viewer',
      resources: { Participant: 'dfsp-a', Report: 'dfspSettlement' },
    });
    expect(parseInstance('hub-operator')).toEqual({ role: 'hub-operator', resources: {} });
  });
});

describe('the document routing the server', () => {
  it('answers by the document: unknown path 404, undeclared method 405, invalid body 400', async () => {
    const { app } = await setup();
    expect((await request(app).get('/no-such-route')).status).toBe(404);
    expect((await request(app).delete('/catalog')).status).toBe(405);
    const invalid = await request(app).post('/subjects/alice/assignments').send({ resources: {} });
    expect(invalid.status).toBe(400);
    expect(invalid.body.errors[0].message).toContain('role');
  });

  it('refuses to start on an operation with no handler', async () => {
    const keto = new MemoryKeto();
    const provisioner = new Provisioner(keto, roles, indexCatalogs([catalog]));
    const definition = {
      openapi: '3.1.0',
      info: { title: 'IAM', version: '1' },
      paths: {
        '/health': { get: { operationId: 'getHealth', responses: { 200: { description: 'ok' } } } },
        '/surprise': { get: { operationId: 'getSurprise', responses: { 200: { description: 'ok' } } } },
      },
    };
    await expect(buildHandler(provisioner, { catalog: [], roles: { roles: {} } }, definition)).rejects.toThrow(
      /no handler for \[getSurprise\]/,
    );
  });

  it('refuses to start on a handler with no operation', async () => {
    const keto = new MemoryKeto();
    const provisioner = new Provisioner(keto, roles, indexCatalogs([catalog]));
    const definition = {
      openapi: '3.1.0',
      info: { title: 'IAM', version: '1' },
      paths: { '/health': { get: { operationId: 'getHealth', responses: { 200: { description: 'ok' } } } } },
    };
    await expect(buildHandler(provisioner, { catalog: [], roles: { roles: {} } }, definition)).rejects.toThrow(
      /no operation for \[getCatalog/,
    );
  });
});
