import type { Held, NewRole, Role, RoleSpec, ServiceCatalog, Subject } from '../client';
import { fakeIam } from './fake-iam';

export const catalog: ServiceCatalog[] = [
  {
    service: 'ledger',
    title: 'Ledger',
    permissions: [
      {
        id: 'ledger.listEntries',
        operationId: 'listEntries',
        summary: 'Lists entries',
        method: 'GET',
        path: '/entries',
        deprecated: false,
        scopedBy: ['participants'],
        bound: [],
        resourceNames: { participants: 'participant' },
      },
      {
        id: 'ledger.purge',
        operationId: 'purge',
        summary: 'Purges the ledger',
        method: 'POST',
        path: '/purge',
        deprecated: true,
        scopedBy: [],
        bound: [],
        resourceNames: {},
      },
    ],
  },
  {
    service: 'iam',
    title: 'IAM',
    permissions: [
      {
        id: 'iam.assignRole',
        operationId: 'assignRole',
        summary: 'Gives a subject a role',
        method: 'POST',
        path: '/subjects/{subject}/assignments',
        deprecated: false,
        scopedBy: ['roles'],
        bound: [],
        resourceNames: { roles: 'role' },
      },
    ],
  },
];

export const resources = {
  participant: [
    { resourceName: 'participant', id: 'p1' },
    { resourceName: 'participant', id: 'p2' },
  ],
  role: [
    { resourceName: 'role', id: 'reader' },
    { resourceName: 'role', id: 'auditor' },
  ],
};

export const signedIn: Role = {
  name: 'signed-in',
  heldBy: 'authenticated',
  grants: [{ permission: 'ledger.listEntries' }],
  open: [],
  owner: 'deployment',
  ready: { reason: 'Accepted' },
};
export const reader: Role = {
  name: 'reader',
  title: { en: 'Reader', uk: 'Читач' },
  description: 'Reads entries',
  grants: [{ permission: 'ledger.listEntries' }],
  open: ['participant'],
  owner: 'iam',
};
export const auditor: Role = {
  name: 'auditor',
  grants: [{ permission: 'ledger.listEntries', resources: { participant: '$all' } }],
  open: [],
  owner: 'deployment',
  ready: { reason: 'Refused', message: 'unknown permission' },
};

export const alice: Subject = { id: 'alice', kind: 'person', name: 'Alice', email: 'alice@example.test' };
export const robot: Subject = { id: 'robot', kind: 'client' };

export const world = {
  'GET /catalog': { body: catalog },
  'GET /resource-names': {
    body: { participant: { label: 'Participant', members: [] }, role: { label: 'Role', members: [], own: true } },
  },
  'GET /resources': ({ query }: { query: URLSearchParams }) => ({
    body: resources[query.get('resourceName') as keyof typeof resources] ?? [...resources.participant, ...resources.role],
  }),
  'GET /roles': { body: [signedIn, reader, auditor] },
  'GET /subjects': { body: [alice, robot] },
};

/** The world, with its roles kept as they are composed, changed and deleted. */
export const roleStore = (roles: Role[] = [signedIn, reader, auditor]) => {
  let current = roles;
  const named = (name: string | undefined) => current.find((role) => role.name === name);
  return fakeIam({
    ...world,
    'GET /roles': () => ({ body: current }),
    'GET /roles/:role': (_, { role }) => {
      const found = named(role);
      return found === undefined ? { status: 404, body: { errors: [`no role ${role}`] } } : { body: found };
    },
    'POST /roles': ({ body }) => {
      const created: Role = { ...(body as NewRole), open: [], owner: 'iam' };
      current = [...current, created];
      return { status: 201, body: created };
    },
    'PUT /roles/:role': ({ body }, { role }) => {
      const changed = { ...(named(role) as Role), ...(body as RoleSpec) };
      current = current.map((kept) => (kept.name === role ? changed : kept));
      return { body: changed };
    },
    'DELETE /roles/:role': (_, { role }) => {
      current = current.filter((kept) => kept.name !== role);
      return { status: 204 };
    },
  });
};

/** The world, with one subject's holdings kept as assignments add to and take from them. */
export const holdings = (held: Held[]) => {
  let current = held;
  return fakeIam({
    ...world,
    'GET /subjects/:subject/assignments': () => ({ body: current }),
    'POST /subjects/:subject/assignments': ({ body }) => {
      current = [...current, { ...(body as Held), through: 'assigned' }];
      return { body: { instance: 'i' } };
    },
    'DELETE /subjects/:subject/assignments': ({ body }) => {
      current = current.filter((h) => h.role !== (body as Held).role);
      return { body: { instance: 'i' } };
    },
  });
};
