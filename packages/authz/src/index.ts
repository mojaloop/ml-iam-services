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
import { UNRESTRICTED, parseScope, type RequestHeaders } from '~/header';
import { accessIn, EVERYTHING, type Access } from '~/access';
import { readDocument, loadDocument } from '~/document';
import { DOCUMENT_PATH, exposeDocument, publish, type Exposed, type Published } from '~/serve';

export { UNRESTRICTED } from '~/header';
export { EVERYTHING, Forbidden } from '~/access';
export type { Access } from '~/access';
export { DOCUMENT_PATH } from '~/serve';
export type { Exposed, Published } from '~/serve';

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
    if (scoping === undefined && !route.resources) {
      throw new GuardError(`${route.operationId} is not scoped by "${type}"`);
    }

    // The gateway checks an id the path carries, so what is left for the
    // service is narrowing its own rows to what the caller holds.
    return accessIn(parseScope((req as RequestLike | undefined)?.headers), type);
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
