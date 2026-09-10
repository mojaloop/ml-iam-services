'use strict';

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
 *   const dfsps = authz(req, 'dfsps');
 *   dfsps.narrow(rows, (row) => row.id)          // a list already in hand
 *   dfsps.allows(id)                             // one id
 *   dfsps.restricted ? model.find(dfsps.ids) : model.find()   // its own query
 *
 * Refusals throw, so a service never renders a reason or picks a status.
 */

const { match } = require('path-to-regexp');
const { UNRESTRICTED, parseScope, idsInScope } = require('./header');
const { readDocument, loadDocument } = require('./document');

class Forbidden extends Error {
  constructor(message) {
    super(message);
    this.name = 'Forbidden';
    /** What a service's error handler renders, whichever framework it is. */
    this.status = 403;
    this.statusCode = 403;
    this.expose = true;
  }
}

class GuardError extends Error {}

/** An OpenAPI path template as a matcher that hands back its parameters by name. */
const matcherFor = (basePath, template) =>
  match(`${basePath}${template}`.replace(/\{([^/}]+)\}/g, ':$1'), { decode: decodeURIComponent });

const pathOf = (req) => {
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
const EVERYTHING = {
  restricted: false,
  ids: [],
  allows: () => true,
  narrow: (rows) => rows,
};

/**
 * What a caller restricted to these ids may reach. A service naming a subset
 * itself — a job that runs for one participant, a test standing in for a
 * request — builds it here, so what it holds is the same thing the guard
 * hands a handler.
 */
const restrictedTo = (ids) => ({
  restricted: true,
  ids,
  allows: (id) => ids.includes(id),
  narrow: (rows, idOf) => rows.filter((row) => ids.includes(idOf(row))),
});

/**
 * A guard for a caller that reaches exactly this, by type. Whatever stands in
 * for a decision — a job that runs for one participant, a test — builds one
 * here, so what a guard is made of stays in this package and a service is
 * given the same thing either way.
 */
const guardReaching = (access, service = '') => {
  const guard = (req, type) => {
    const visible = access[type];
    if (visible === undefined) {
      throw new GuardError(`${service}: this guard was not given "${type}"`);
    }
    return visible;
  };
  guard.scopedBy = () => Object.keys(access);
  guard.service = service;
  return guard;
};

/**
 * Reads a service's API document and answers requests against it.
 *
 * @param {string|object} document  a path to the document, or one already parsed
 * @returns {Promise<Function>} the check to run per request
 */
const createGuard = async (document) => {
  const doc = typeof document === 'string' ? await loadDocument(document) : document;
  const { service, basePath, operations } = readDocument(doc);

  const routes = operations.map((operation) => ({
    ...operation,
    matches: matcherFor(basePath, operation.template),
  }));

  const routeFor = (req) => {
    const method = (req?.method ?? 'GET').toUpperCase();
    const requested = pathOf(req);
    const route = routes.find(
      (candidate) => candidate.method === method && candidate.matches(requested) !== false,
    );
    if (route === undefined) {
      throw new GuardError(`${service}: ${method} ${requested} is not an operation this document declares`);
    }
    return route;
  };

  const check = (req, type) => {
    if (typeof type !== 'string' || type === '') {
      throw new GuardError(`${service}: ask for a resource type this document declares`);
    }

    if (req === UNRESTRICTED) return EVERYTHING;

    const route = routeFor(req);
    const scoping = route.scopedBy.find((declared) => declared.type === type);
    if (scoping === undefined) {
      throw new GuardError(`${service}: ${route.operationId} is not scoped by "${type}"`);
    }

    const ids = idsInScope(parseScope(req?.headers), type);
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
  check.scopedBy = (req) =>
    req === UNRESTRICTED
      ? []
      : routeFor(req)
          .scopedBy.filter((scoping) => scoping.param === undefined)
          .map((scoping) => scoping.type);

  check.service = service;
  return check;
};

module.exports = { createGuard, guardReaching, UNRESTRICTED, EVERYTHING, restrictedTo, Forbidden, GuardError };
