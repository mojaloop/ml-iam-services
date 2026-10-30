import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { AdmissionContext, review } from '../../src/operator/webhook';

const admission = (document: unknown) => ({
  apiVersion: 'admission.k8s.io/v1',
  kind: 'AdmissionReview',
  request: {
    uid: 'u-1',
    operation: 'CREATE',
    object: { metadata: { name: 'hubble-ui', namespace: 'cilium' }, spec: { document } },
  },
});

const document = (summary?: string) => ({
  openapi: '3.1.0',
  info: { title: 'Hubble UI', version: '1.0' },
  paths: {
    '/': {
      get: {
        operationId: 'view',
        ...(summary !== undefined ? { summary } : {}),
        'x-authz': { scopedBy: [] },
        responses: { 200: { description: 'The application' } },
      },
    },
  },
});

describe('AuthzDocument admission', () => {
  it('admits a document the composition can read, answering the review it was asked', async () => {
    expect((await review(admission(document('Opens the UI')))).response).toEqual({ uid: 'u-1', allowed: true });
  });

  it('refuses a document the composition would refuse, with its reason', async () => {
    expect((await review(admission(document()))).response).toEqual({
      uid: 'u-1',
      allowed: false,
      status: { code: 422, message: 'GET /: summary is required for the catalog' },
    });
  });

  it('refuses a document older than OpenAPI 3.1', async () => {
    const answer = await review(admission({ ...document('Opens the UI'), openapi: '3.0.3' }));
    expect(answer.response).toMatchObject({
      allowed: false,
      status: { message: 'AuthzDocument/cilium/hubble-ui: OpenAPI 3.0 is not supported; the document must declare 3.1 or later' },
    });
  });

  it('refuses a document written as text', async () => {
    const answer = await review(admission('openapi: 3.1.0'));
    expect(answer.response).toMatchObject({
      allowed: false,
      status: { message: 'AuthzDocument/cilium/hubble-ui: spec.document is not an OpenAPI document' },
    });
  });
});

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
    permissions: [
      permission('ledger.read'),
      permission('ledger.create', ['participants']),
      permission('ledger.approve', ['participants']),
    ],
  },
];

const object = (kind: string, name: string, spec: unknown, namespace = 'mcm', uid = `${namespace}-${name}`) => ({
  kind,
  metadata: { name, namespace, uid },
  spec,
});

const reviewing = (kind: string, incoming: unknown, oldObject?: unknown) => ({
  request: { uid: 'u-2', operation: oldObject === undefined ? 'CREATE' : 'UPDATE', kind: { kind }, object: incoming, oldObject },
});

const context = (stored: Record<string, unknown[]> = {}, holders = 0): AdmissionContext => ({
  catalog,
  stored: async (kind) => (stored[kind] ?? []) as never,
  holders: async () => holders,
});

const message = async (body: unknown, ctx: AdmissionContext) =>
  (await review(body, ctx)).response as { allowed: boolean; status?: { message: string } };

describe('AuthzRole admission', () => {
  it('admits a role over composed permissions', async () => {
    const role = object('AuthzRole', 'reader', { grants: [{ permission: 'ledger.read' }] });
    expect((await message(reviewing('AuthzRole', role), context())).allowed).toBe(true);
  });

  it('admits a role naming a service not composed yet, which then waits', async () => {
    const role = object('AuthzRole', 'payer', { grants: [{ permission: 'payouts.create' }] });
    expect((await message(reviewing('AuthzRole', role), context())).allowed).toBe(true);
  });

  it('refuses a permission a composed service does not offer', async () => {
    const role = object('AuthzRole', 'typo', { grants: [{ permission: 'ledger.raed' }] });
    const answer = await message(reviewing('AuthzRole', role), context());
    expect(answer.allowed).toBe(false);
    expect(answer.status?.message).toContain('typo: unknown permission ledger.raed');
  });

  it('refuses a name another namespace already holds', async () => {
    const held = object('AuthzRole', 'reader', { grants: [{ permission: 'ledger.read' }] }, 'ory');
    const again = object('AuthzRole', 'reader', { grants: [{ permission: 'ledger.read' }] }, 'mcm');
    const answer = await message(reviewing('AuthzRole', again), context({ AuthzRole: [held] }));
    expect(answer.status?.message).toBe(
      'AuthzRole/mcm/reader: reader is already defined by AuthzRole/ory/reader; a name is unique across the cluster',
    );
  });

  it('admits an edit of the object that holds the name', async () => {
    const role = object('AuthzRole', 'reader', { grants: [{ permission: 'ledger.read' }] });
    expect((await message(reviewing('AuthzRole', role, role), context({ AuthzRole: [role] }))).allowed).toBe(true);
  });

  it('refuses a role whose own grants span a separation rule', async () => {
    const rule = object('AuthzSeparation', 'maker-checker', { groups: [['ledger.create'], ['ledger.approve']] });
    const role = object('AuthzRole', 'both', {
      grants: [{ permission: 'ledger.create' }, { permission: 'ledger.approve' }],
    });
    const answer = await message(reviewing('AuthzRole', role), context({ AuthzSeparation: [rule] }));
    expect(answer.allowed).toBe(false);
    expect(answer.status?.message).toContain('both: its grants span maker-checker');
  });

  it('refuses a role every subject holds, which the decision does not answer for yet', async () => {
    const role = object('AuthzRole', 'signed-in', { heldBy: 'authenticated', grants: [{ permission: 'ledger.read' }] });
    const answer = await message(reviewing('AuthzRole', role), context());
    expect(answer.allowed).toBe(false);
    expect(answer.status?.message).toContain('the decision does not yet answer for a role every signed-in subject holds');
  });

  it('refuses a role every subject holds that leaves a resource open', async () => {
    const role = object('AuthzRole', 'signed-in', { heldBy: 'authenticated', grants: [{ permission: 'ledger.create' }] });
    expect((await message(reviewing('AuthzRole', role), context())).status?.message).toContain('cannot leave participant open');
  });

  it('refuses a role every subject holds whose permission is in a separation group', async () => {
    const rule = object('AuthzSeparation', 'maker-checker', { groups: [['ledger.read'], ['ledger.approve']] });
    const role = object('AuthzRole', 'signed-in', { heldBy: 'authenticated', grants: [{ permission: 'ledger.read' }] });
    const answer = await message(reviewing('AuthzRole', role), context({ AuthzSeparation: [rule] }));
    expect(answer.status?.message).toContain('ledger.read is in a separation group');
  });

  it('refuses making an assigned role every subject’s, saying how many hold it', async () => {
    const before = object('AuthzRole', 'reader', { grants: [{ permission: 'ledger.read' }] });
    const after = object('AuthzRole', 'reader', { heldBy: 'authenticated', grants: [{ permission: 'ledger.read' }] });
    const answer = await message(reviewing('AuthzRole', after, before), context({}, 3));
    expect(answer.status?.message).toContain('3 subjects are assigned it');
  });

  it('refuses while the IAM has composed nothing to check against', async () => {
    const role = object('AuthzRole', 'reader', { grants: [{ permission: 'ledger.read' }] });
    const answer = await message(reviewing('AuthzRole', role), { ...context(), catalog: undefined });
    expect(answer.status?.message).toBe('AuthzRole/mcm/reader: the IAM has composed nothing yet to check it against');
  });
});

describe('AuthzSeparation admission', () => {
  it('admits a rule naming a service not composed yet', async () => {
    const rule = object('AuthzSeparation', 'later', { groups: [['payouts.create'], ['ledger.approve']] });
    expect((await message(reviewing('AuthzSeparation', rule), context())).allowed).toBe(true);
  });

  it('refuses an unknown permission of a composed service', async () => {
    const rule = object('AuthzSeparation', 'typo', { groups: [['ledger.craete'], ['ledger.approve']] });
    expect((await message(reviewing('AuthzSeparation', rule), context())).status?.message).toContain(
      'typo: unknown permission ledger.craete',
    );
  });

  it('refuses a resource rule naming no declared resource name', async () => {
    const rule = object('AuthzSeparation', 'per-dfsp', {
      within: 'resource',
      resourceName: 'dfsp',
      groups: [['ledger.create'], ['ledger.approve']],
    });
    expect((await message(reviewing('AuthzSeparation', rule), context())).status?.message).toContain(
      'per-dfsp: no resource name called dfsp',
    );
  });

  it('admits a resource rule over permissions its resource name scopes', async () => {
    const rule = object('AuthzSeparation', 'per-dfsp', {
      within: 'resource',
      resourceName: 'participant',
      groups: [['ledger.create'], ['ledger.approve']],
    });
    const names = [object('AuthzResourceName', 'participant', { members: [{ service: 'ledger', type: 'participants' }] }, 'ory')];
    expect((await message(reviewing('AuthzSeparation', rule), context({ AuthzResourceName: names }))).allowed).toBe(true);
  });
});

describe('AuthzResourceName admission', () => {
  it('admits a member of a service not composed yet', async () => {
    const name = object('AuthzResourceName', 'report', { members: [{ service: 'reports', type: 'reports' }] }, 'ory');
    expect((await message(reviewing('AuthzResourceName', name), context())).allowed).toBe(true);
  });

  it('refuses a member type its composed service is not about', async () => {
    const name = object('AuthzResourceName', 'participant', { members: [{ service: 'ledger', type: 'dfsps' }] }, 'ory');
    expect((await message(reviewing('AuthzResourceName', name), context())).status?.message).toContain(
      'resource name participant lists ledger.dfsps, which ledger is not about',
    );
  });

  it('refuses a source whose id is not a pointer', async () => {
    const name = object(
      'AuthzResourceName',
      'participant',
      { members: [{ service: 'ledger', type: 'participants' }], source: { url: 'http://ledger/participants', id: 'name' } },
      'ory',
    );
    expect((await message(reviewing('AuthzResourceName', name), context())).status?.message).toContain(
      'source.id "name" is not a JSON Pointer',
    );
  });
});
