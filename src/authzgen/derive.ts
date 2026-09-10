import { DocumentError, readDocument } from '@mojaloop/authz/document';

import { Permission, ScopedType, ServiceBundle } from './types';

/**
 * Derivation: an annotated OpenAPI document in, the authorization model of
 * that service out. The rules are fixed platform-wide, so two services with
 * the same shape always produce the same authorization structure.
 *
 * What `x-authz` means is read by the package a service's own guard reads it
 * with, so the deploy-time conclusion and the runtime one cannot differ. What
 * is added here is what only the gateway needs: which capture group carries a
 * bound id, and which authenticator each security scheme maps to.
 *
 *   permission id   <service>.<x-authz.permission ?? operationId>
 *   scoped by       x-authz.scopedBy ?? [the type of the outermost parameter]
 *   resource type   the literal segment preceding a path parameter
 *   bound type      a scoping type the path binds an id for; it is checked as
 *                   <type>/<id>, and every scoping type is handed to the
 *                   service to narrow by, whether bound or not
 *   singleton       an operation with no bound type, checked against __self__
 *   anonymous       native `security: []`
 *   authenticators  the security schemes, mapped by platform convention
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
type Doc = any;

/** Platform convention: an OpenAPI security scheme maps to one authenticator. */
export const AUTHENTICATOR_BY_SCHEME: Record<string, string> = {
  'apiKey:cookie': 'cookie_session',
  'http:bearer': 'jwt',
  'oauth2:': 'jwt',
  'openIdConnect:': 'jwt',
};

/**
 * Path parameters in path order. Capture-group index 0 is the scheme group,
 * so path captures start at 1; every parameter consumes an index whether or
 * not it names a type, and disambiguation lookaheads are not capturing.
 */
const pathParams = (path: string): string[] =>
  path
    .split('/')
    .filter(Boolean)
    .flatMap((segment) => (segment.startsWith('{') && segment.endsWith('}') ? [segment.slice(1, -1)] : []));

const authenticatorsFor = (security: Doc, schemes: Doc, where: string): string[] => {
  const handlers = new Set<string>();
  for (const requirement of security) {
    for (const scheme of Object.keys(requirement)) {
      const declared = schemes?.[scheme];
      if (!declared) throw new DocumentError(`${where}: security scheme "${scheme}" is not declared`);
      const key = `${declared.type}:${declared.type === 'apiKey' ? declared.in : declared.scheme ?? ''}`;
      const handler = AUTHENTICATOR_BY_SCHEME[key];
      if (!handler) {
        throw new DocumentError(`${where}: security scheme "${scheme}" (${key}) has no authenticator mapping`);
      }
      handlers.add(handler);
    }
  }
  return [...handlers];
};

export function derive(doc: Doc): ServiceBundle {
  const root = doc['x-authz'] ?? {};
  for (const key of Object.keys(root)) {
    if (key !== 'service' && key !== 'resourceTypes') {
      throw new DocumentError(`the document root: unknown x-authz key "${key}"`);
    }
  }
  if (
    root.resourceTypes !== undefined &&
    (!Array.isArray(root.resourceTypes) || root.resourceTypes.some((t: unknown) => typeof t !== 'string'))
  ) {
    throw new DocumentError('x-authz.resourceTypes must be an array of resource types');
  }

  const { service, basePath, operations } = readDocument(doc);
  const schemes = doc.components?.securitySchemes;

  const permissions: Permission[] = operations.map((operation) => {
    const where = `${operation.method} ${operation.template}`;
    const params = pathParams(operation.template);
    const node = doc.paths[operation.template][operation.method.toLowerCase()];

    // Checks are emitted in capture order, so bound types sort by their
    // capture index and types the path does not bind follow them.
    const scopedBy: ScopedType[] = operation.scopedBy
      .map((scoping): ScopedType =>
        scoping.param === undefined
          ? { type: scoping.type }
          : { type: scoping.type, param: scoping.param, captureIndex: params.indexOf(scoping.param) + 1 },
      )
      .sort((a, b) => (a.captureIndex ?? Infinity) - (b.captureIndex ?? Infinity));

    return {
      id: operation.permission,
      name: operation.permission.slice(service.length + 1),
      operationId: operation.operationId,
      method: operation.method,
      path: operation.template,
      summary: operation.summary,
      deprecated: operation.deprecated,
      anonymous: operation.anonymous,
      authenticators: operation.anonymous ? ['noop'] : authenticatorsFor(node.security, schemes, where),
      scopedBy,
    };
  });

  // A type is grantable in this service when some operation declares it. The
  // root list authors the same set, and checking the two against each other is
  // what catches a type one operation misspells among fifty.
  const resourceTypes = [...new Set(permissions.flatMap((p) => p.scopedBy.map((r) => r.type)))].sort();
  if (root.resourceTypes === undefined) {
    if (resourceTypes.length > 0) {
      throw new DocumentError(
        `the document is about [${resourceTypes.join(', ')}]; declare them in x-authz.resourceTypes at the root`,
      );
    }
  } else {
    const authored = new Set<string>(root.resourceTypes);
    for (const type of resourceTypes) {
      if (!authored.has(type)) {
        throw new DocumentError(`operations use resource type "${type}", which x-authz.resourceTypes does not declare`);
      }
    }
    for (const type of authored) {
      if (!resourceTypes.includes(type)) {
        throw new DocumentError(`x-authz.resourceTypes declares "${type}", which no operation uses`);
      }
    }
  }

  const ids = permissions.map((p) => p.id);
  const duplicate = ids.find((id, i) => ids.indexOf(id) !== i);
  if (duplicate) throw new DocumentError(`duplicate permission id "${duplicate}"`);

  return {
    service,
    title: doc.info?.title ?? service,
    basePath,
    permissions,
    resourceTypes,
  };
}
