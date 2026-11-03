import { DOCUMENT_PATH, DocumentGuard, Forbidden } from '@mojaloop/authz';
import { FastifyInstance, FastifyRequest } from 'fastify';
import { StatusCodes } from 'http-status-codes';

import { Localized } from '../authzgen/compose';
import { CALLER_HEADER } from '../authzgen/emit-rules';
import { permissionId } from '../authzgen/permission';
import type { Composition } from '../controller/api';
import { Answer, documentServer, param, query } from '../http/backend';
import { refusal } from '../http/status';
import { Reason } from '../iam/conditions';
import { heldPermission, holdersOf, Named, Reach, writeProblems } from '../iam/holdings';
import { KetoReads } from '../iam/keto';
import { API_VERSION, Kind, MANAGED_BY } from '../iam/kinds';
import type { SessionPermissions } from '../iam/kratos';
import { AUTHENTICATED, HELD_BY, ROLE_NAMESPACE } from '../iam/materialize';
import { ownRoleName, OwnType } from '../iam/own';
import { assignmentsOf, subjectsHolding } from '../iam/provisioner';
import { ResourceInstance } from '../iam/registry';
import { RoleView } from '../iam/role-sync';
import {
  ALL,
  indexCatalogs,
  namedByProblem,
  openResourceNames,
  PermissionIndex,
  RoleGrant,
  rolesNaming,
} from '../iam/roles';
import { Logged } from '../logged';
import type { AuthzRole } from '../operator/cluster';
import { Document, documentAt } from './documents';
import type { Identities } from './identities';
import {
  COMPOSITION_EVENT,
  ControllerPath,
  Header,
  HEALTHY,
  JSON_MEDIA,
  Method,
  Operation,
  Owner,
  Param,
  Through,
} from './vocabulary';

/** A refusal a handler raises, answered as `{errors}` with its status. */
class Refusal extends Error {
  constructor(
    readonly statusCode: number,
    message: string,
  ) {
    super(message);
  }
}

/** The name a fetch's error carries when a later read cancelled it. */
const ABORTED = 'AbortError';

/** The composition as this process holds it. */
export interface CompositionSource {
  /** Whether what is held is older than what the controller announced. */
  readonly behind: boolean;
  /** The ETag of what is held, once anything is. */
  readonly etag: string | undefined;
  /** Reads what the controller serves now. */
  read(): Promise<void>;
  now(): Composition;
  index(): PermissionIndex;
  /** Calls back with the ETag of each composition held from now on, until the returned function is called. */
  onChange(listener: (etag: string) => void): () => void;
}

/**
 * The composition as the controller last announced it. A change of the
 * announced ETag starts a read, and a read started later cancels one still
 * running, so the copy held is never older than what the controller said.
 */
export class Feed implements CompositionSource {
  current?: Composition;
  etag: string | undefined = undefined;
  wanted?: string;
  private reading?: AbortController;
  private indexed?: { etag: string | undefined; index: PermissionIndex };
  private readonly listeners = new Set<(etag: string) => void>();

  constructor(private readonly controllerUrl: string) {}

  onChange(listener: (etag: string) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  get behind(): boolean {
    return this.current === undefined || (this.wanted !== undefined && this.wanted !== this.etag);
  }

  async read(): Promise<void> {
    this.reading?.abort();
    const reading = new AbortController();
    this.reading = reading;
    const response = await fetch(`${this.controllerUrl}${ControllerPath.composition}`, {
      headers: this.etag !== undefined ? { [Header.ifNoneMatch]: this.etag } : {},
      signal: reading.signal,
    });
    if (response.status === StatusCodes.NOT_MODIFIED) return;
    if (!response.ok) throw new Error(`the controller answered ${response.status}`);
    const composition = (await response.json()) as Composition;
    const previous = this.etag;
    this.current = composition;
    this.etag = response.headers.get(Header.etag) ?? undefined;
    if (this.etag !== undefined && this.etag !== previous) {
      for (const listener of this.listeners) listener(this.etag);
    }
  }

  readSoon(): void {
    this.read().catch((error) => {
      if ((error as Error).name !== ABORTED) {
        console.error(JSON.stringify({ event: Logged.compositionReadFailed, error: String(error) }));
      }
    });
  }

  now(): Composition {
    if (this.current === undefined) throw new Refusal(StatusCodes.SERVICE_UNAVAILABLE, 'the IAM has not composed anything yet');
    return this.current;
  }

  index(): PermissionIndex {
    if (this.indexed === undefined || this.indexed.etag !== this.etag) {
      this.indexed = { etag: this.etag, index: indexCatalogs(this.now().catalog) };
    }
    return this.indexed.index;
  }
}

/** The roles composed here, as Kubernetes objects in the IAM's namespace. */
export interface RoleStore {
  get(name: string): Promise<AuthzRole | undefined>;
  create(role: AuthzRole): Promise<void>;
  apply(role: AuthzRole): Promise<void>;
  delete(name: string): Promise<void>;
}

/** What a Kubernetes refusal says, or nothing when the error is not one. */
export const refusedBy = (error: unknown): { status: number; message: string } | undefined => {
  const response = error as { status?: number; data?: { message?: string } };
  return typeof response.status === 'number' && refusal(response.status)
    ? { status: response.status, message: response.data?.message ?? String(response.status) }
    : undefined;
};

/** Asks the controller, with a body for a write or a query for a read, and answers what it answered. */
export type Controller = (
  method: Method,
  path: ControllerPath,
  body?: unknown,
  search?: Record<string, string>,
) => Promise<Answer>;

export const controllerAt =
  (url: string): Controller =>
    async (method, path, body, search) => {
      const target = new URL(path, url);
      for (const [name, value] of Object.entries(search ?? {})) target.searchParams.set(name, value);
      const response = await fetch(target, {
        method,
        ...(body !== undefined ? { headers: { [Header.contentType]: JSON_MEDIA }, body: JSON.stringify(body) } : {}),
      });
      return { status: response.status, body: await response.json() };
    };

/** What the controller lists for an operator to choose among. */
interface Listing {
  resources: ResourceInstance[];
  stale: Record<string, unknown>;
}

export type People = Pick<
  Identities,
  'subjects' | 'account' | 'deleteAccount' | 'createClient' | 'rotate' | 'deleteClient' | 'writePermissions'
>;

export interface ApiState {
  namespace: string;
  /** Reads only: every write goes through the controller. */
  keto: KetoReads;
  composition: CompositionSource;
  identities: People;
  roles: RoleStore;
  controller: Controller;
}

const owned = (labels: Record<string, string> | undefined, at: string | undefined, namespace: string): boolean =>
  Object.entries(MANAGED_BY).every(([key, value]) => labels?.[key] === value) && at === namespace;

interface RoleSpecIn {
  title?: Localized;
  description?: Localized;
  grants: RoleGrant[];
}

const specOf = (body: RoleSpecIn): RoleSpecIn => ({
  ...(body.title !== undefined ? { title: body.title } : {}),
  ...(body.description !== undefined ? { description: body.description } : {}),
  grants: body.grants,
});

/** What an assignment write is handed to the controller as, by the operation that asks for it. */
const ASSIGNMENT_WRITE = {
  [Operation.assignRole]: Method.post,
  [Operation.unassignRole]: Method.delete,
} as const;

/**
 * What people and the UIs they use ask, through the gateway. Every
 * operation is a permission the gateway already decided; what is left here
 * is that nobody hands out access they do not hold, unless their scope for
 * the operation names it.
 */
export async function publicApi(state: ApiState, guard: DocumentGuard): Promise<FastifyInstance> {
  const { namespace, keto, composition, identities, roles } = state;

  /** The subject the gateway authenticated, which the IAM's rules hand on. */
  const caller = (req: FastifyRequest): string => {
    const subject = req.headers[CALLER_HEADER];
    if (typeof subject !== 'string' || subject === '') throw new Refusal(StatusCodes.UNAUTHORIZED, 'the gateway named no caller');
    return subject;
  };

  /** What the caller's scope for this operation names: every one, some, or none, when only holding counts. */
  const scopeOf = (req: FastifyRequest, type: string): Named => {
    try {
      const access = guard(req, type);
      return access.restricted ? access.ids : ALL;
    } catch (error) {
      if (error instanceof Forbidden) return [];
      throw error;
    }
  };

  /** What the caller's scope for one of these operations reaches of each resource name, by whichever type it spells it with. */
  const reachOf = (req: FastifyRequest, operation: Operation): Reach => {
    const now = composition.now();
    const permission = now.servesAs === undefined ? undefined : composition.index().get(permissionId(now.servesAs, operation));
    return Object.fromEntries(
      Object.entries(permission?.resourceNames ?? {}).map(([type, resourceName]) => [resourceName, scopeOf(req, type)]),
    );
  };

  const within = (reach: Named | undefined, id: string): boolean => reach === ALL || (reach ?? []).includes(id);

  const roleOut = (view: RoleView) => ({
    name: view.name,
    ...(view.title !== undefined ? { title: view.title } : {}),
    ...(view.description !== undefined ? { description: view.description } : {}),
    ...(view.heldBy !== undefined ? { heldBy: view.heldBy } : {}),
    grants: view.grants,
    open: view.open,
    owner: owned(view.labels, view.namespace, namespace) ? Owner.iam : Owner.deployment,
    ready: view.ready,
  });

  /** The object holding a name, preferring the one the IAM accepted over a refused duplicate. */
  const viewOf = (name: string): RoleView | undefined => {
    const views = composition.now().roles.filter((r) => r.name === name);
    return views.find((r) => r.ready.reason !== Reason.refused) ?? views[0];
  };

  const written = (name: string, spec: RoleSpecIn) => ({
    name,
    ...spec,
    open: openResourceNames(spec, composition.index()),
    owner: Owner.iam,
  });

  const object = (name: string, spec: RoleSpecIn) =>
    ({
      apiVersion: API_VERSION,
      kind: Kind.role,
      metadata: { name, namespace, labels: MANAGED_BY },
      spec,
    }) as unknown as AuthzRole;

  /** Refuses a role the deployment keeps elsewhere, and one that does not exist. */
  const ownRole = async (name: string): Promise<void> => {
    const stored = await roles.get(name);
    if (stored !== undefined && owned(stored.metadata?.labels, stored.metadata?.namespace, namespace)) return;
    if (stored !== undefined || composition.now().roles.some((r) => r.name === name)) {
      throw new Refusal(StatusCodes.CONFLICT, `${name} is the deployment's role; it changes where the deployment keeps it`);
    }
    throw new Refusal(StatusCodes.NOT_FOUND, `no role called ${name}`);
  };

  const writeChecked = async (
    req: FastifyRequest,
    operation: typeof Operation.createRole | typeof Operation.updateRole,
    spec: RoleSpecIn,
  ): Promise<void> => {
    const held = await holdersOf(keto, caller(req));
    const problems = writeProblems(spec, composition.index(), held, {
      permissions: scopeOf(req, OwnType.permissions),
      reach: reachOf(req, operation),
    });
    if (problems.length > 0) throw new Refusal(StatusCodes.UNPROCESSABLE_ENTITY, problems.join('; '));
  };

  /** A write Kubernetes refuses, admission included, answered with its reason. */
  const admitted = async (write: () => Promise<unknown>): Promise<void> => {
    try {
      await write();
    } catch (error) {
      const refusal = refusedBy(error);
      if (refusal === undefined || refusal.status >= StatusCodes.INTERNAL_SERVER_ERROR) throw error;
      throw new Refusal(refusal.status === StatusCodes.CONFLICT ? StatusCodes.CONFLICT : StatusCodes.UNPROCESSABLE_ENTITY, refusal.message);
    }
  };

  const assignment = async (req: FastifyRequest, operation: keyof typeof ASSIGNMENT_WRITE) =>
    state.controller(ASSIGNMENT_WRITE[operation], ControllerPath.assignments, {
      ...(req.body as object),
      subject: param(req, Param.subject),
      by: { subject: caller(req), roles: scopeOf(req, OwnType.roles), reach: reachOf(req, operation) },
    });

  const document = guard.published;
  return documentServer(
    documentAt(Document.public),
    {
      getHealth: () => ({ status: StatusCodes.OK, body: HEALTHY }),
      getCatalog: () => ({ status: StatusCodes.OK, body: composition.now().catalog }),
      getResourceNames: () => ({ status: StatusCodes.OK, body: composition.now().resourceNames }),
      listResources: async (req) => {
        const reach = reachOf(req, Operation.listResources);
        const resourceName = query(req, Param.resourceName);
        const answer = await state.controller(
          Method.get,
          ControllerPath.resources,
          undefined,
          resourceName !== undefined ? { [Param.resourceName]: resourceName } : {},
        );
        if (answer.status !== StatusCodes.OK) return answer;
        const { resources, stale } = answer.body as Listing;
        const unread = Object.keys(stale).sort();
        return {
          status: StatusCodes.OK,
          body: resources.filter((r) => within(reach[r.resourceName], r.id)),
          ...(unread.length > 0 ? { headers: { [Header.staleSources]: unread.join(',') } } : {}),
        };
      },
      listRoles: (req) => {
        const visible = scopeOf(req, OwnType.roles);
        return { status: StatusCodes.OK, body: composition.now().roles.filter((r) => within(visible, r.name)).map(roleOut) };
      },
      getRole: (req) => {
        const name = param(req, Param.role);
        const view = viewOf(name);
        if (view === undefined) throw new Refusal(StatusCodes.NOT_FOUND, `no role called ${name}`);
        return { status: StatusCodes.OK, body: roleOut(view) };
      },
      createRole: async (req) => {
        const body = req.body as RoleSpecIn & { name: string };
        const spec = specOf(body);
        await writeChecked(req, Operation.createRole, spec);
        await admitted(() => roles.create(object(body.name, spec)));
        console.log(JSON.stringify({ event: Logged.roleCreated, role: body.name }));
        return { status: StatusCodes.CREATED, body: written(body.name, spec) };
      },
      updateRole: async (req) => {
        const name = param(req, Param.role);
        const spec = specOf(req.body as RoleSpecIn);
        await ownRole(name);
        await writeChecked(req, Operation.updateRole, spec);
        await admitted(() => roles.apply(object(name, spec)));
        console.log(JSON.stringify({ event: Logged.roleUpdated, role: name }));
        return { status: StatusCodes.OK, body: written(name, spec) };
      },
      deleteRole: async (req) => {
        const name = param(req, Param.role);
        await ownRole(name);
        const holding = await subjectsHolding(keto, name);
        if (holding.length > 0) throw new Refusal(StatusCodes.CONFLICT, `${holding.length} subjects hold ${name}; take it from them first`);
        const now = composition.now();
        const naming = rolesNaming(
          name,
          Object.fromEntries(now.roles.map((view) => [view.name, { grants: view.grants }])),
          ownRoleName(now.catalog, now.servesAs),
        );
        if (naming.length > 0) throw new Refusal(StatusCodes.CONFLICT, namedByProblem(name, naming));
        await roles.delete(name);
        console.log(JSON.stringify({ event: Logged.roleDeleted, role: name }));
        return { status: StatusCodes.NO_CONTENT };
      },
      listSubjects: async () => ({ status: StatusCodes.OK, body: await identities.subjects() }),
      getAssignments: async (req) => {
        const subject = param(req, Param.subject);
        const assigned = (await assignmentsOf(keto, subject)).map((a) => ({ ...a, through: Through.assigned }));
        const everyone = (await keto.query({ namespace: ROLE_NAMESPACE, relation: HELD_BY, subject_id: AUTHENTICATED })).map(
          (t) => ({ role: t.object, resources: {}, through: Through.authenticated }),
        );
        return { status: StatusCodes.OK, body: [...assigned, ...everyone] };
      },
      assignRole: (req) => assignment(req, Operation.assignRole),
      unassignRole: (req) => assignment(req, Operation.unassignRole),
      getState: () => {
        const now = composition.now();
        return {
          status: StatusCodes.OK,
          body: {
            services: now.catalog.map((c) => ({ service: c.service, permissions: c.permissions.length })),
            roles: now.roles.map((r) => ({ name: r.name, ready: r.ready })),
            separations: now.separations.map((s) => ({ name: s.name, ready: s.ready, violations: s.violations })),
            pending: now.pending,
            ...(now.applied !== undefined ? { applied: now.applied } : {}),
            renamed: now.renamed,
            removed: now.removed,
          },
        };
      },
      getChanges: {
        events: async (_req, res) => {
          res.sse.keepAlive();
          res.sse.sendHeaders();
          const tell = (etag: string): void => {
            res.sse.send({ id: etag, event: COMPOSITION_EVENT, data: { etag } }).catch(() => res.sse.close());
          };
          res.sse.onClose(composition.onChange(tell));
          if (composition.etag !== undefined && res.sse.lastEventId !== composition.etag) tell(composition.etag);
        },
      },
    },
    {},
    (app) => {
      app.get(DOCUMENT_PATH, async (req, res) =>
        req.headers[Header.ifNoneMatch] === document.etag
          ? res.code(StatusCodes.NOT_MODIFIED).header(Header.etag, document.etag).send()
          : res.code(StatusCodes.OK).header(Header.etag, document.etag).type(JSON_MEDIA).send(document.body),
      );
    },
  );
}

/**
 * The provisioning authority's API, reachable only by what a network rule
 * names. A person or a client is retired only once they hold no role.
 */
export async function internalApi(state: ApiState): Promise<FastifyInstance> {
  const { keto, composition, identities } = state;

  const retire = async (subject: string, remove: () => Promise<boolean>): Promise<Answer> => {
    const held = await assignmentsOf(keto, subject);
    if (held.length > 0) throw new Refusal(StatusCodes.CONFLICT, `${subject} still holds ${held.map((h) => h.role).join(', ')}`);
    await remove();
    console.log(JSON.stringify({ event: Logged.retired, subject }));
    return { status: StatusCodes.NO_CONTENT };
  };

  return documentServer(documentAt(Document.internal), {
    getHealth: async () => {
      if (composition.behind) await composition.read().catch(() => undefined);
      if (composition.behind) throw new Refusal(StatusCodes.SERVICE_UNAVAILABLE, 'the composition the controller announced is not read yet');
      return { status: StatusCodes.OK, body: HEALTHY };
    },
    provisionResource: (req) => state.controller(Method.post, ControllerPath.resources, req.body),
    deprovisionResource: (req) => state.controller(Method.delete, ControllerPath.resources, req.body),
    createAccount: async (req) => {
      const body = req.body as { email: string; name?: string };
      const account = await identities.account(body.email, body.name);
      console.log(JSON.stringify({ event: Logged.account, subject: account.subject, created: account.created, invited: account.invited }));
      return { status: StatusCodes.OK, body: account };
    },
    deleteAccount: (req) => retire(param(req, Param.subject), () => identities.deleteAccount(param(req, Param.subject))),
    createClient: async (req) => {
      const body = req.body as { id?: string; name?: string; audience?: string[] };
      const created = await identities.createClient(body);
      if (created === undefined) throw new Refusal(StatusCodes.CONFLICT, `a client called ${body.id} already exists`);
      console.log(JSON.stringify({ event: Logged.clientCreated, subject: created.subject }));
      return { status: StatusCodes.CREATED, body: created };
    },
    rotateClientSecret: async (req) => {
      const subject = param(req, Param.subject);
      const rotated = await identities.rotate(subject);
      if (rotated === undefined) throw new Refusal(StatusCodes.NOT_FOUND, `no client called ${subject}`);
      console.log(JSON.stringify({ event: Logged.secretRotated, subject: rotated.subject }));
      return { status: StatusCodes.OK, body: rotated };
    },
    deleteClient: (req) => retire(param(req, Param.subject), () => identities.deleteClient(param(req, Param.subject))),
    assignRole: (req) =>
      state.controller(Method.post, ControllerPath.assignments, { ...(req.body as object), subject: param(req, Param.subject) }),
    unassignRole: (req) =>
      state.controller(Method.delete, ControllerPath.assignments, { ...(req.body as object), subject: param(req, Param.subject) }),
    login: async (req) => {
      const subject = (req.body as { identity_id: string }).identity_id;
      const held = await holdersOf(keto, subject);
      const index = composition.index();
      const permissions: SessionPermissions = {};
      for (const id of index.keys()) {
        const answer = heldPermission(id, index, held);
        if (answer.held) permissions[id] = answer.resources ?? {};
      }
      await identities.writePermissions(subject, permissions);
      console.log(JSON.stringify({ event: Logged.permissionsWritten, subject, permissions: Object.keys(permissions).length }));
      return { status: StatusCodes.NO_CONTENT };
    },
  });
}
