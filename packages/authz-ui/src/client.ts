import createClient from 'openapi-fetch';

import type { components, paths } from './generated/public';

export { type Localized, localize } from './localize';
export type { components, paths };

type Schemas = components['schemas'];

export type ResourceSet = Schemas['ResourceSet'];
export type Grant = Schemas['Grant'];
export type RoleSpec = Schemas['RoleSpec'];
export type NewRole = Schemas['NewRole'];
export type Role = Schemas['Role'];
export type Verdict = Schemas['Verdict'];
export type Assignment = Schemas['Assignment'];
export type Held = Schemas['Held'];
export type Subject = Schemas['Subject'];
export type Resource = Schemas['Resource'];
export type CatalogPermission = Schemas['CatalogPermission'];
export type ServiceCatalog = Schemas['ServiceCatalog'];
export type ResourceName = Schemas['ResourceName'];
export type Instance = Schemas['Instance'];
export type State = Schemas['State'];
export type Problems = Schemas['Problems'];

export { ALL } from '@mojaloop/authz/reserved';

/** Who keeps a role: the IAM, which composed it through its API, or the deployment. */
export const Owner = { iam: 'iam', deployment: 'deployment' } as const satisfies Record<string, Role['owner']>;

/** What the IAM made of a role it has read. */
export const VerdictReason = {
  accepted: 'Accepted',
  refused: 'Refused',
  waiting: 'Waiting',
} as const satisfies Record<string, Verdict['reason']>;

/** Who holds a role without an assignment. */
export const HeldBy = { authenticated: 'authenticated' } as const satisfies Record<string, NonNullable<Role['heldBy']>>;

/** How a subject holds a role: assigned it, or as every signed-in subject does. */
export const Through = {
  assigned: 'assigned',
  authenticated: 'authenticated',
} as const satisfies Record<string, Held['through']>;

export const SubjectKind = { person: 'person', client: 'client' } as const satisfies Record<string, Subject['kind']>;

/**
 * A request the API answered with something other than success. `errors` are
 * the reasons the IAM gave; a refusal that did not come from the IAM, such as
 * the gateway's, may carry none, and `status` tells it apart.
 */
export class AuthzError extends Error {
  readonly status: number;
  readonly errors: string[];

  constructor(status: number, errors: string[], statusText = '') {
    super(errors.length > 0 ? errors.join('; ') : `${status} ${statusText}`.trim());
    this.name = 'AuthzError';
    this.status = status;
    this.errors = errors;
  }
}

const reasons = (body: unknown): string[] => {
  if (typeof body !== 'object' || body === null) return [];
  const { errors } = body as { errors?: unknown };
  return Array.isArray(errors) ? errors.filter((e): e is string => typeof e === 'string') : [];
};

interface Answered<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

async function answer<T>(pending: Promise<Answered<T>>): Promise<T> {
  const { data, error, response } = await pending;
  if (!response.ok) throw new AuthzError(response.status, reasons(error), response.statusText);
  return data as T;
}

export type RequestOptions = {
  signal?: AbortSignal;
};

export interface AuthzClientOptions {
  /** Where the gateway serves the IAM's public API, absolute or relative to the page. */
  baseUrl: string;
  fetch?: (request: Request) => Promise<Response>;
  /** What opens the change stream; the browser's own when absent. */
  EventSource?: typeof EventSource;
}

export interface ChangeWatch {
  /** Called with the composition's ETag on connecting, and each time what the IAM applied changes. */
  onChange(etag: string): void;
  /** Called when the stream fails; the browser reconnects a dropped stream itself, and closes one the gateway refused. */
  onError?(event: Event): void;
}

export interface Resources {
  resources: Resource[];
  /** The resource names whose source did not answer: what they list is the IAM's last good read. */
  stale: string[];
}

export interface AuthzClient {
  getCatalog(options?: RequestOptions): Promise<ServiceCatalog[]>;
  getResourceNames(options?: RequestOptions): Promise<Record<string, ResourceName>>;
  listResources(resourceName?: string, options?: RequestOptions): Promise<Resources>;
  listRoles(options?: RequestOptions): Promise<Role[]>;
  getRole(role: string, options?: RequestOptions): Promise<Role>;
  createRole(role: NewRole, options?: RequestOptions): Promise<Role>;
  updateRole(role: string, spec: RoleSpec, options?: RequestOptions): Promise<Role>;
  deleteRole(role: string, options?: RequestOptions): Promise<void>;
  listSubjects(options?: RequestOptions): Promise<Subject[]>;
  getAssignments(subject: string, options?: RequestOptions): Promise<Held[]>;
  assignRole(subject: string, assignment: Assignment, options?: RequestOptions): Promise<Instance>;
  unassignRole(subject: string, assignment: Assignment, options?: RequestOptions): Promise<Instance>;
  getState(options?: RequestOptions): Promise<State>;
  /**
   * Streams `GET /changes`: each change to the catalog, the roles and rules
   * and their verdicts. Assignments are not part of it. Answers what closes
   * the stream.
   */
  watchChanges(watch: ChangeWatch): () => void;
}

/**
 * The IAM's public API as the gateway serves it. Every request carries the
 * browser's cookies, since the session cookie is what the gateway
 * authenticates.
 */
export function createAuthzClient({ baseUrl, fetch, EventSource: Source }: AuthzClientOptions): AuthzClient {
  const api = createClient<paths>({ baseUrl, credentials: 'include', fetch });
  const changes = `${baseUrl.replace(/\/$/, '')}/changes`;

  return {
    getCatalog: (options) => answer(api.GET('/catalog', options)),
    getResourceNames: (options) => answer(api.GET('/resource-names', options)),
    listResources: async (resourceName, options) => {
      const read = await api.GET('/resources', { ...options, params: { query: { resourceName } } });
      const resources = await answer(Promise.resolve(read));
      const stale = (read.response.headers.get('stale-sources') ?? '')
        .split(',')
        .map((name) => name.trim())
        .filter((name) => name !== '');
      return { resources, stale };
    },
    listRoles: (options) => answer(api.GET('/roles', options)),
    getRole: (role, options) => answer(api.GET('/roles/{role}', { ...options, params: { path: { role } } })),
    createRole: (role, options) => answer(api.POST('/roles', { ...options, body: role })),
    updateRole: (role, spec, options) =>
      answer(api.PUT('/roles/{role}', { ...options, params: { path: { role } }, body: spec })),
    deleteRole: (role, options) =>
      answer<void>(api.DELETE('/roles/{role}', { ...options, params: { path: { role } } })),
    listSubjects: (options) => answer(api.GET('/subjects', options)),
    getAssignments: (subject, options) =>
      answer(api.GET('/subjects/{subject}/assignments', { ...options, params: { path: { subject } } })),
    assignRole: (subject, assignment, options) =>
      answer(
        api.POST('/subjects/{subject}/assignments', { ...options, params: { path: { subject } }, body: assignment }),
      ),
    unassignRole: (subject, assignment, options) =>
      answer(
        api.DELETE('/subjects/{subject}/assignments', { ...options, params: { path: { subject } }, body: assignment }),
      ),
    getState: (options) => answer(api.GET('/state', options)),
    watchChanges: ({ onChange, onError }) => {
      const Stream = Source ?? globalThis.EventSource;
      if (Stream === undefined) throw new Error('no EventSource here: pass one to createAuthzClient');
      const stream = new Stream(changes, { withCredentials: true });
      stream.addEventListener('composition', (event) => onChange((event as MessageEvent).lastEventId));
      if (onError !== undefined) stream.addEventListener('error', onError);
      return () => stream.close();
    },
  };
}
