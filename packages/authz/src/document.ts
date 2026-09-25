/**
 * The one reading of `x-authz`.
 *
 * A document says which resource types an operation is about and where a
 * request names one of them. Everything downstream follows from that: the
 * gateway rules and the permission model at deploy time, and this package's
 * guard at request time. Both read it here, so a service cannot be generated
 * against one interpretation and enforced against another.
 *
 *   x-authz:                            # on an operation
 *     scopedBy: [orders]                # the types its answer is scoped by
 *
 * A type the path binds an id for is checked by the gateway as `<type>/<id>`.
 * Every scoping type, bound or not, reaches the service as what the caller
 * holds of it, which is what the service narrows its own rows by.
 *
 * A document names no service and no permission. The route carries the
 * authorization namespace, and a permission is `<that>.<operationId>`, so one
 * image serving two routes answers under each route's own namespace.
 */

import fs from 'node:fs';
import { parse as parseYaml } from 'yaml';

/** Where a request names an id of one resource type. */
export interface Scoping {
  type: string;
  /** The path parameter carrying the id, when the path binds one. */
  param?: string;
}

/** What one operation says about authorization, read from a document. */
export interface DeclaredOperation {
  operationId: string;
  method: string;
  /** The OpenAPI path template, before any base path. */
  template: string;
  summary: string;
  deprecated: boolean;
  /** Whether the answer is a list of the rows a type names. */
  list: boolean;
  /** The resource types the answer is scoped by, and where the path carries an id. */
  scopedBy: Scoping[];
}

export interface ReadDocument {
  basePath: string;
  operations: DeclaredOperation[];
}

/** A `scopedBy` entry as written: a bare type, or one `type: parameter` binding. */
type ScopedByEntry = string | Record<string, string>;

interface AuthzBlock {
  scopedBy?: ScopedByEntry[];
}

interface MediaType {
  schema?: { type?: string | string[] };
}

interface OperationNode {
  operationId?: string;
  summary?: string;
  deprecated?: boolean;
  responses?: Record<string, { content?: Record<string, MediaType | undefined> } | undefined>;
  'x-authz'?: unknown;
}

interface PathItemNode {
  /** Methods OpenAPI has no fixed field for, keyed by the method as it is sent. */
  additionalOperations?: Record<string, OperationNode | undefined>;
}

interface DocumentNode {
  openapi?: string;
  servers?: { url?: string }[];
  paths?: Record<string, PathItemNode | undefined>;
}

export const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'head', 'options', 'trace', 'query'];

/** A document that cannot be read as an authorization surface. */
export class DocumentError extends Error {}

const segments = (template: string): string[] => template.split('/').filter((part) => part !== '');

const paramName = (segment: string): string | undefined =>
  segment.startsWith('{') && segment.endsWith('}') ? segment.slice(1, -1) : undefined;

/** Path parameters in path order. */
const pathParams = (template: string): string[] =>
  segments(template)
    .map(paramName)
    .filter((param): param is string => param !== undefined);

/**
 * The types the path itself carries an id for. A segment naming a type is
 * followed by the parameter carrying its id: `/orders/{orderId}`,
 * `/customers/{customerId}`.
 */
export const boundTypes = (template: string): Map<string, string> => {
  const parts = segments(template);
  const bound = new Map<string, string>();
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
const isArray = (schema: MediaType['schema']): boolean => {
  const type = schema?.type;
  return Array.isArray(type) ? type.includes('array') : type === 'array';
};

const returnsArray = (operation: OperationNode): boolean =>
  Object.entries(operation.responses ?? {}).some(
    ([status, response]) =>
      status.startsWith('2') && Object.values(response?.content ?? {}).some((media) => isArray(media?.schema)),
  );

/**
 * Every operation on a path, by the method it answers. A method with no fixed
 * field of its own is declared under `additionalOperations`, whose keys carry
 * the method already spelled as it is sent.
 */
const operationsOf = (item: PathItemNode | undefined): [string, OperationNode][] => {
  const fixed = item as Record<string, OperationNode | undefined> | undefined;
  const found: [string, OperationNode][] = [];
  for (const method of METHODS) {
    const operation = fixed?.[method];
    if (operation) found.push([method.toUpperCase(), operation]);
  }
  for (const [method, operation] of Object.entries(item?.additionalOperations ?? {})) {
    if (operation) found.push([method, operation]);
  }
  return found;
};

const readAuthz = (node: OperationNode, where: string): AuthzBlock => {
  const authz = node['x-authz'];
  if (authz === undefined) return {};
  if (typeof authz !== 'object' || authz === null || Array.isArray(authz)) {
    throw new DocumentError(`${where}: x-authz must be an object`);
  }
  const block = authz as AuthzBlock;
  const known = new Set(['scopedBy']);
  for (const key of Object.keys(block)) {
    if (!known.has(key)) throw new DocumentError(`${where}: unknown x-authz key "${key}"`);
  }
  if (block.scopedBy !== undefined) {
    if (!Array.isArray(block.scopedBy)) {
      throw new DocumentError(`${where}: x-authz.scopedBy must be an array`);
    }
    for (const entry of block.scopedBy) {
      const one =
        typeof entry === 'object' && entry !== null && !Array.isArray(entry) && Object.keys(entry).length === 1;
      if (typeof entry !== 'string' && !(one && typeof Object.values(entry)[0] === 'string')) {
        throw new DocumentError(
          `${where}: a scopedBy entry is a type, or one \`type: parameter\` binding, got ${JSON.stringify(entry)}`,
        );
      }
    }
    const types = block.scopedBy.map((entry) => (typeof entry === 'string' ? entry : Object.keys(entry)[0]));
    const duplicate = types.find((type, at) => types.indexOf(type) !== at);
    if (duplicate !== undefined) throw new DocumentError(`${where}: x-authz.scopedBy lists "${duplicate}" twice`);
  }
  return block;
};

/**
 * A written scopedBy is the whole truth: a `type: parameter` entry binds that
 * parameter as the type's id, and a bare entry declares the type unbound. A
 * bare entry naming a type the path binds would read as bound and not be, so
 * it is refused.
 */
const scopedByOf = (
  entries: ScopedByEntry[],
  template: string,
  bound: Map<string, string>,
  where: string,
): Scoping[] => {
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
export const basePathOf = (doc: unknown): string => {
  const url = (doc as DocumentNode)?.servers?.[0]?.url ?? '';
  const base = url.startsWith('http') ? new URL(url).pathname : url;
  return base === '/' ? '' : base.replace(/\/$/, '');
};

/**
 * Every operation the document declares, with what a decision about it needs:
 * the resource types it is about, where an id of each is named, and whether
 * its answer is a list the service narrows itself.
 */
export const readDocument = (doc: unknown): ReadDocument => {
  const root = doc as DocumentNode | undefined;

  const operations: DeclaredOperation[] = [];
  for (const [template, item] of Object.entries(root?.paths ?? {})) {
    for (const [method, operation] of operationsOf(item)) {
      const where = `${method} ${template}`;

      if (!operation.operationId) throw new DocumentError(`${where}: operationId is required`);
      if (!operation.summary) throw new DocumentError(`${where}: summary is required for the catalog`);

      const authz = readAuthz(operation, where);
      const bound = boundTypes(template);
      const list = returnsArray(operation);

      if (method === 'GET' && bound.size === 0 && authz.scopedBy === undefined && list) {
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
        method,
        template,
        summary: operation.summary,
        deprecated: operation.deprecated === true,
        /** A list of the rows a type names, which the service narrows itself. */
        list,
        /** Each entry carries the path parameter holding an id, when the path binds one. */
        scopedBy: declared,
      });
    }
  }

  return { basePath: basePathOf(root), operations };
};

/**
 * Reads a document from disk, YAML or JSON. Authorization is derived from the
 * paths and their `x-authz`, which every document in this platform writes
 * inline, so the reading here is the same reading the generator does at
 * deploy time. A `$ref` in a schema is data the guard never looks at.
 */
export const loadDocument = async (file: string): Promise<unknown> => {
  const text = await fs.promises.readFile(file, 'utf8');
  const doc = file.endsWith('.json') ? JSON.parse(text) : parseYaml(text);
  const version = String((doc as DocumentNode)?.openapi ?? '');
  if (!version.startsWith('3.')) {
    throw new DocumentError(`${file}: OpenAPI ${version || '(none)'} is not a version this platform speaks`);
  }
  return doc;
};
