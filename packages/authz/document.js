'use strict';

/**
 * The one reading of `x-authz`.
 *
 * A document says which resource types an operation is about and where a
 * request names one of them. Everything downstream follows from that: the
 * gateway rules and the permission model at deploy time, and this package's
 * guard at request time. Both read it here, so a service cannot be generated
 * against one interpretation and enforced against another.
 *
 *   x-authz:
 *     service: mcm                      # once, at the document root
 *
 *   x-authz:                            # on an operation
 *     permission: getDfspStatus         # defaults to operationId
 *     scopedBy: [dfsps]                 # the types its answer is scoped by
 *
 * A type the path binds an id for is checked by the gateway as `<type>/<id>`.
 * Every scoping type, bound or not, reaches the service as what the caller
 * holds of it, which is what the service narrows its own rows by.
 */

const fs = require('node:fs');
const { parse: parseYaml } = require('yaml');

const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'head', 'options'];

class DocumentError extends Error {}

const segments = (template) => template.split('/').filter((part) => part !== '');

const paramName = (segment) => (segment.startsWith('{') && segment.endsWith('}') ? segment.slice(1, -1) : undefined);

/** Path parameters in path order. */
const pathParams = (template) => segments(template).map(paramName).filter((param) => param !== undefined);

/**
 * The types the path itself carries an id for. A segment naming a type is
 * followed by the parameter carrying its id, which is the shape every
 * Mojaloop API already uses: `/dfsps/{dfspId}`, `/reports/{reportName}`.
 */
const boundTypes = (template) => {
  const parts = segments(template);
  const bound = new Map();
  parts.forEach((segment, at) => {
    const param = paramName(segment);
    if (param === undefined) return;
    const preceding = at > 0 ? parts[at - 1] : undefined;
    if (preceding === undefined || paramName(preceding) !== undefined) return;
    if (!bound.has(preceding)) bound.set(preceding, param);
  });
  return bound;
};

/**
 * Whether the operation answers with a list of the rows a type names. Such an
 * operation narrows its own answer, so a request that names nobody is the
 * caller asking for their own; anything else cannot be narrowed after the
 * fact, and a caller holding some of a type has to say which.
 */
const returnsArray = (operation) =>
  Object.entries(operation.responses ?? {}).some(
    ([status, response]) =>
      status.startsWith('2') &&
      Object.values(response?.content ?? {}).some((media) => media?.schema?.type === 'array'),
  );

const readAuthz = (node, where) => {
  const authz = node?.['x-authz'];
  if (authz === undefined) return {};
  if (typeof authz !== 'object' || Array.isArray(authz)) {
    throw new DocumentError(`${where}: x-authz must be an object`);
  }
  const known = new Set(['permission', 'scopedBy']);
  for (const key of Object.keys(authz)) {
    if (!known.has(key)) throw new DocumentError(`${where}: unknown x-authz key "${key}"`);
  }
  if (authz.permission !== undefined && typeof authz.permission !== 'string') {
    throw new DocumentError(`${where}: x-authz.permission must be a string`);
  }
  if (authz.scopedBy !== undefined) {
    if (!Array.isArray(authz.scopedBy)) {
      throw new DocumentError(`${where}: x-authz.scopedBy must be an array`);
    }
    for (const entry of authz.scopedBy) {
      const one = typeof entry === 'object' && entry !== null && !Array.isArray(entry) && Object.keys(entry).length === 1;
      if (typeof entry !== 'string' && !(one && typeof Object.values(entry)[0] === 'string')) {
        throw new DocumentError(
          `${where}: a scopedBy entry is a type, or one \`type: parameter\` binding, got ${JSON.stringify(entry)}`,
        );
      }
    }
    const types = authz.scopedBy.map((entry) => (typeof entry === 'string' ? entry : Object.keys(entry)[0]));
    const duplicate = types.find((type, at) => types.indexOf(type) !== at);
    if (duplicate !== undefined) throw new DocumentError(`${where}: x-authz.scopedBy lists "${duplicate}" twice`);
  }
  return authz;
};

/**
 * A written scopedBy is the whole truth: a `type: parameter` entry binds that
 * parameter as the type's id, and a bare entry declares the type unbound. A
 * bare entry naming a type the path binds would read as bound and not be, so
 * it is refused.
 */
const scopedByOf = (entries, template, bound, where) => {
  const params = pathParams(template);
  return entries.map((entry) => {
    if (typeof entry === 'string') {
      const param = bound.get(entry);
      if (param !== undefined) {
        throw new DocumentError(
          `${where}: the path binds ${entry} through {${param}}; write \`${entry}: ${param}\` or a bare type the path does not bind`,
        );
      }
      return { type: entry };
    }
    const [type, param] = Object.entries(entry)[0];
    if (!params.includes(param)) {
      throw new DocumentError(`${where}: scopedBy binds ${type} to {${param}}, which is not a parameter of this path`);
    }
    return { type, param };
  });
};

/** The base path from the first server entry, without a trailing slash. */
const basePathOf = (doc) => {
  const url = doc.servers?.[0]?.url ?? '';
  const base = url.startsWith('http') ? new URL(url).pathname : url;
  return base === '/' ? '' : base.replace(/\/$/, '');
};

/**
 * Every operation the document declares, with what a decision about it needs:
 * the resource types it is about, where an id of each is named, and whether
 * its answer is a list the service narrows itself.
 *
 * @param {object} doc  a parsed OpenAPI document
 * @returns {{service: string, basePath: string, operations: object[]}}
 */
const readDocument = (doc) => {
  const service = doc?.['x-authz']?.service;
  if (typeof service !== 'string' || service === '') {
    throw new DocumentError('the document root must declare x-authz.service');
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(service)) {
    throw new DocumentError(`x-authz.service "${service}" is not a name a Keto namespace can take`);
  }

  const operations = [];
  for (const [template, item] of Object.entries(doc.paths ?? {})) {
    for (const method of METHODS) {
      const operation = item?.[method];
      if (!operation) continue;
      const where = `${method.toUpperCase()} ${template}`;

      if (!operation.operationId) throw new DocumentError(`${where}: operationId is required`);
      if (!operation.summary) throw new DocumentError(`${where}: summary is required for the catalog`);
      if (operation.security === undefined) {
        throw new DocumentError(`${where}: security must be declared explicitly on every operation`);
      }

      const authz = readAuthz(operation, where);
      const bound = boundTypes(template);
      const anonymous = Array.isArray(operation.security) && operation.security.length === 0;
      const list = returnsArray(operation);

      if (method === 'get' && !anonymous && bound.size === 0 && authz.scopedBy === undefined && list) {
        throw new DocumentError(
          `${where}: returns a list and binds no resource id, so x-authz.scopedBy must name the row type, or be [] to declare the rows unscoped`,
        );
      }

      // By default an operation is scoped by the resource its outermost
      // parameter identifies; types deeper in the path are business data
      // inside it.
      const declared =
        authz.scopedBy !== undefined
          ? scopedByOf(authz.scopedBy, template, bound, where)
          : [...bound.entries()].slice(0, 1).map(([type, param]) => ({ type, param }));

      operations.push({
        operationId: operation.operationId,
        permission: `${service}.${authz.permission ?? operation.operationId}`,
        method: method.toUpperCase(),
        template,
        summary: operation.summary,
        deprecated: operation.deprecated === true,
        anonymous,
        /** A list of the rows a type names, which the service narrows itself. */
        list,
        /** Each entry carries the path parameter holding an id, when the path binds one. */
        scopedBy: declared,
      });
    }
  }

  return { service, basePath: basePathOf(doc), operations };
};

/**
 * Reads a document from disk, YAML or JSON. Authorization is derived from the
 * paths and their `x-authz`, which every document in this platform writes
 * inline, so the reading here is the same reading the generator does at
 * deploy time. A `$ref` in a schema is data the guard never looks at.
 *
 * @param {string} file
 * @returns {Promise<object>}
 */
const loadDocument = async (file) => {
  const text = await fs.promises.readFile(file, 'utf8');
  const doc = file.endsWith('.json') ? JSON.parse(text) : parseYaml(text);
  const version = String(doc?.openapi ?? '');
  if (!version.startsWith('3.')) {
    throw new DocumentError(`${file}: OpenAPI ${version || '(none)'} is not a version this platform speaks`);
  }
  return doc;
};

module.exports = { DocumentError, readDocument, loadDocument, boundTypes, basePathOf, METHODS };
