/**
 * What a service is allowed to answer.
 *
 * A service hands over its own API document and asks, per request, what the
 * caller may see of one of the resource types that document declares. Every
 * other decision belongs to the platform and is made in here: how the answer
 * travels from the endpoint that decided it, what an unnamed request means,
 * and when to refuse. A service that wants a different policy is a service
 * with its own security model, which is the thing this package exists to
 * prevent.
 *
 *   const authz = await createGuard('./src/api/openapi.yaml');
 *
 *   const orders = authz(req, 'orders');
 *   orders.narrow(rows, (row) => row.id)         // a list already in hand
 *   orders.allows(id)                            // one id
 *   orders.restricted ? model.find(orders.ids) : model.find()   // its own query
 *
 * Refusals throw, so a service never renders a reason or picks a status.
 */

import { match } from 'path-to-regexp';
import { UNRESTRICTED, parseScope, idsInScope, type RequestHeaders } from '~/header';
import { readDocument, loadDocument } from '~/document';
import { DOCUMENT_PATH, exposeDocument, publish, type Exposed, type Published } from '~/serve';

export { UNRESTRICTED } from '~/header';
export { DOCUMENT_PATH } from '~/serve';
export type { Exposed, Published } from '~/serve';

/** What a caller may reach of one resource type. */
export interface Access {
  /** Whether anything limits this caller. */
  restricted: boolean;
  /** The ids it may reach; empty when nothing restricts it. */
  ids: string[];
  /** Whether this caller may reach one id. */
  allows(id: string): boolean;
  /** The members of a list in hand it may reach. */
  narrow<T>(rows: T[], idOf: (row: T) => string): T[];
}

export interface Guard {
  (req: unknown, type: string): Access;
  /** The types this request's operation hands the service to narrow its own answer by. */
  scopedBy(req?: unknown): string[];
}

/**
 * A guard holding the document it was built from, which it hands over so the
 * platform reads what this guard enforces.
 */
export interface DocumentGuard extends Guard {
  /** Where the platform reads it, for a server routing it under its own framework. */
  path: string;
  /** The document itself, for a server that routes it under its own framework. */
  document: unknown;
  /** The bytes and their digest, for a server that writes its own response. */
  published: Published;
  /**
   * A handler for express or a bare `http` server. Mount it ahead of a router
   * that would refuse a path its own document does not describe.
   */
  expose(): Exposed;
}

/** A request as whichever framework the service runs hands it over. */
interface RequestLike {
  url?: string;
  originalUrl?: string;
  method?: string;
  headers?: RequestHeaders;
}

/** A request the caller may not make. Carries `status` 403 for any framework. */
export class Forbidden extends Error {
  /** What a service's error handler renders, whichever framework it is. */
  readonly status = 403;
  readonly statusCode = 403;
  readonly expose = true;

  constructor(message: string) {
    super(message);
    this.name = 'Forbidden';
  }
}

/** A service asking something its own document does not describe. */
export class GuardError extends Error {}

/** An OpenAPI path template as a matcher that hands back its parameters by name. */
const matcherFor = (basePath: string, template: string) =>
  match(`${basePath}${template}`.replace(/\{([^/}]+)\}/g, ':$1'), { decode: decodeURIComponent });

const pathOf = (req: RequestLike | undefined): string => {
  const url = req?.url ?? req?.originalUrl ?? '';
  const at = url.indexOf('?');
  return at === -1 ? url : url.slice(0, at);
};

/**
 * Every id reachable, for a caller nothing restricts. Exported so a service
 * calling its own internals passes it by name, which keeps an unrestricted
 * read something someone wrote rather than something a missing scope caused.
 *
 * `ids` is empty here rather than absent, so a service that builds a query
 * from it without asking `restricted` first shows nothing instead of showing
 * the whole table. The careless branch is the closed one.
 */
export const EVERYTHING: Access = {
  restricted: false,
  ids: [],
  allows: () => true,
  narrow: (rows) => rows,
};

/**
 * What a caller restricted to these ids may reach. A service naming a subset
 * itself — a job that runs for a single id, a test standing in for a
 * request — builds it here, so what it holds is the same thing the guard
 * hands a handler.
 */
export const restrictedTo = (ids: string[]): Access => ({
  restricted: true,
  ids,
  allows: (id) => ids.includes(id),
  narrow: (rows, idOf) => rows.filter((row) => ids.includes(idOf(row))),
});

/**
 * A guard for a caller that reaches exactly this, by type. Whatever stands in
 * for a decision — a job that runs for a single id, a test — builds one
 * here, so what a guard is made of stays in this package and a service is
 * given the same thing either way.
 */
export const guardReaching = (access: Record<string, Access>): Guard => {
  const guard = (_req: unknown, type: string): Access => {
    const visible = access[type];
    if (visible === undefined) {
      throw new GuardError(`this guard was not given "${type}"`);
    }
    return visible;
  };
  return Object.assign(guard, { scopedBy: (): string[] => Object.keys(access) });
};

/**
 * Reads a service's API document and answers requests against it.
 *
 * @param document  a path to the document, or one already parsed
 */
export const createGuard = async (document: string | object): Promise<DocumentGuard> => {
  const doc = typeof document === 'string' ? await loadDocument(document) : document;
  const { basePath, operations } = readDocument(doc);

  const routes = operations.map((operation) => ({
    ...operation,
    matches: matcherFor(basePath, operation.template),
  }));

  const routeFor = (req: unknown) => {
    const request = req as RequestLike | undefined;
    const method = (request?.method ?? 'GET').toUpperCase();
    const requested = pathOf(request);
    const route = routes.find(
      (candidate) => candidate.method === method && candidate.matches(requested) !== false,
    );
    if (route === undefined) {
      throw new GuardError(`${method} ${requested} is not an operation this document declares`);
    }
    return route;
  };

  const check = (req: unknown, type: string): Access => {
    if (typeof type !== 'string' || type === '') {
      throw new GuardError('ask for a resource type this document declares');
    }

    if (req === UNRESTRICTED) return EVERYTHING;

    const route = routeFor(req);
    const scoping = route.scopedBy.find((declared) => declared.type === type);
    if (scoping === undefined) {
      throw new GuardError(`${route.operationId} is not scoped by "${type}"`);
    }

    const ids = idsInScope(parseScope((req as RequestLike | undefined)?.headers), type);
    if (ids === undefined) return EVERYTHING;
    if (ids.length === 0) throw new Forbidden(`this caller may reach no ${type}`);

    // The gateway checks an id the path carries, so what is left for the
    // service is narrowing its own rows to what the caller holds.
    return restrictedTo(ids);
  };

  /**
   * The types this request's operation hands the service to narrow its own
   * answer by: the ones it is scoped by that the path carries no id for. An
   * id in the path was checked by the gateway, so nothing is left to do for
   * it here.
   */
  const scopedBy = (req?: unknown): string[] =>
    req === UNRESTRICTED
      ? []
      : routeFor(req)
          .scopedBy.filter((scoping) => scoping.param === undefined)
          .map((scoping) => scoping.type);

  const published = publish(doc);
  const exposed = exposeDocument(published);

  return Object.assign(check, {
    scopedBy,
    path: DOCUMENT_PATH,
    document: doc,
    published,
    expose: () => exposed,
  });
};
