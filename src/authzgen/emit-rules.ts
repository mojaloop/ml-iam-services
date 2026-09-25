import { DOCUMENT_PATH } from '@mojaloop/authz';

import { ketoNamespace } from './keto-name';
import { Permission, ServiceBundle } from './types';

/**
 * Oathkeeper access rules, one per operation. Matches must be mutually
 * disjoint or Oathkeeper answers 500, so a templated segment that competes
 * with literal siblings at the same position carries a negative lookahead
 * listing them, and a rule owning a subtree excludes every path something
 * else on the same host answers. Every rule is the same skeleton; only the
 * payload varies.
 */

const escape = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const trimSlash = (path: string): string => path.replace(/\/+$/, '');

const segments = (path: string): string[] => path.split('/').filter(Boolean);
const paramName = (s: string): string | undefined =>
  s.startsWith('{') && s.endsWith('}') ? s.slice(1, -1) : undefined;

/**
 * Literal segments that appear at the same position, under the same prefix,
 * as this templated segment. Excluding them is what keeps `/things/{id}`
 * from also matching a sibling `/things/summary`.
 */
const competingLiterals = (path: string, index: number, allPaths: string[]): string[] => {
  const prefix = segments(path).slice(0, index);
  const literals = new Set<string>();
  for (const other of allPaths) {
    if (other === path) continue;
    const parts = segments(other);
    if (parts.length <= index) continue;
    const matchesPrefix = prefix.every((segment, i) => {
      const theirs = parts[i]!;
      return segment === theirs || paramName(segment) !== undefined || paramName(theirs) !== undefined;
    });
    if (!matchesPrefix) continue;
    const candidate = parts[index]!;
    if (paramName(candidate) === undefined) literals.add(candidate);
  }
  return [...literals].sort();
};

/** A route rewriting the client's path prefix `from` into `to` before the backend sees it. */
export interface Rewrite {
  from: string;
  to: string;
}

/** A client path a route sends to the backend: one path, or a prefix and everything under it. */
export interface Mount {
  type: 'Exact' | 'PathPrefix';
  path: string;
  method?: string;
}

/**
 * Where the service is served. The document cannot know this, so the
 * deployment supplies it; without it the match keeps the placeholders for a
 * later substitution step.
 */
export interface Serving {
  /** The hostnames the route answers on; a leading `*.` matches one label. */
  hosts?: string[];
  rewrite?: Rewrite;
  /** Client path prefixes other backends answer on the same hosts. */
  exclude?: string[];
  /** What the route sends to this backend; a rule never matches past it. */
  within?: Mount[];
  /**
   * The authenticators this deployment accepts on an authorized route, in the
   * order Oathkeeper should try them.
   */
  authenticators?: string[];
}

/** What a deployment accepts when it names nothing. */
const AUTHENTICATORS = ['cookie_session', 'jwt'];

/**
 * The path a client sends for a path the backend sees, or nothing when the
 * rewrite never produces it.
 */
export const clientPath = (backendPath: string, rewrite?: Rewrite): string | undefined => {
  if (rewrite === undefined) return backendPath;
  const from = trimSlash(rewrite.from);
  const to = trimSlash(rewrite.to);
  if (to !== '' && backendPath !== to && !backendPath.startsWith(`${to}/`)) return undefined;
  return `${from}${backendPath.slice(to.length)}`;
};

const hostPattern = (host: string): string =>
  host.startsWith('*.') ? `[^.]+\\.${escape(host.slice(2))}` : escape(host);

/** The host part of a match: literal for one plain host, an alternation otherwise. */
const hostPart = (hosts: string[] | undefined): string => {
  if (hosts === undefined || hosts.length === 0) return '{host}';
  if (hosts.length === 1 && !hosts[0]!.startsWith('*.')) return hosts[0]!;
  return `<${[...hosts].sort().map(hostPattern).join('|')}>`;
};

/** The client prefix the service's base path answers at. */
const prefixOf = (bundle: ServiceBundle, serving: Serving): string => {
  if (serving.hosts === undefined && serving.rewrite === undefined) return `{path}${bundle.basePath}`;
  const prefix = clientPath(bundle.basePath, serving.rewrite);
  if (prefix === undefined) {
    throw new Error(
      `${bundle.service}: the route rewrites ${serving.rewrite!.from} to ${serving.rewrite!.to}, which never reaches ${bundle.basePath}`,
    );
  }
  return prefix;
};

const methodAllows = (mount: Mount, method?: string): boolean =>
  method === undefined || mount.method === undefined || mount.method.toUpperCase() === method.toUpperCase();

/** Whether a route sending this mount sends everything under the prefix. */
const covers = (mount: Mount, prefix: string): boolean => {
  if (mount.type !== 'PathPrefix') return false;
  const path = trimSlash(mount.path);
  return path === '' || prefix === path || prefix.startsWith(`${path}/`);
};

/**
 * The parts of the subtree at `prefix` the route sends, relative to it, or
 * nothing when it sends the whole subtree.
 */
const reachedUnder = (prefix: string, serving: Serving, method?: string): string[] | undefined => {
  if (serving.within === undefined) return undefined;
  const mounts = serving.within.filter((mount) => methodAllows(mount, method));
  if (mounts.some((mount) => covers(mount, prefix))) return undefined;
  const alternatives = mounts.flatMap((mount) => {
    const path = mount.type === 'PathPrefix' ? trimSlash(mount.path) : mount.path;
    if (path !== prefix && !path.startsWith(`${prefix}/`)) return [];
    const relative = escape(path.slice(prefix.length));
    return [mount.type === 'PathPrefix' ? `${relative}(?:/.*)?` : relative];
  });
  return [...new Set(alternatives)].sort();
};

/** Whether the route sends any request under `prefix` to this backend. */
export const reachesSubtree = (mounts: Mount[], method: string, prefix: string): boolean => {
  const at = trimSlash(prefix);
  const under = reachedUnder(at, { within: mounts }, method);
  return under === undefined || under.length > 0;
};

/**
 * A prefix and everything under it the route sends here, less what the
 * backend's document path and other backends on the same hosts answer: two
 * rules matching one request is a 500, so the subtree gives those paths up.
 */
const subtree = (prefix: string, serving: Serving, method?: string): string => {
  const within = (path: string): string | undefined =>
    prefix === '' ? path : path === prefix || path.startsWith(`${prefix}/`) ? path.slice(prefix.length) : undefined;

  const document = clientPath(DOCUMENT_PATH, serving.rewrite);
  const excluded = [
    ...(document === undefined ? [] : [within(document)]),
    ...(serving.exclude ?? []).map((path) => within(trimSlash(path))),
  ].filter((path): path is string => path !== undefined && path !== '');

  const guards = [...new Set(excluded)].sort().map((path) => `${escape(path)}(?:/|$)`);
  const guard = guards.length ? `(?!${guards.join('|')})` : '';
  const reached = reachedUnder(prefix, serving, method);
  return reached === undefined ? `<${guard}(?:/.*)?>` : `<${guard}(?:${reached.join('|')})>`;
};

/** Oathkeeper match expression for one operation. */
export const matchUrl = (
  permission: Permission,
  bundle: ServiceBundle,
  allPaths: string[],
  serving: Serving = {},
): string => {
  const parts = segments(permission.path).map((segment, index) => {
    const param = paramName(segment);
    if (param === undefined) return segment;
    const competing = competingLiterals(permission.path, index, allPaths);
    const guard = competing.length ? `<?!${competing.join('|')}>` : '';
    return `${guard}<(?<${param}>[^/]+)>`;
  });
  const path = parts.length ? `/${parts.join('/')}` : '';
  const prefix = prefixOf(bundle, serving);
  // An operation at the root is the mount itself, and a mount owns the URL
  // space under it: one permission for an application whose own routes are
  // resolved past the gateway. An operation under a path answers at that path.
  const extent = parts.length ? '<$>' : subtree(prefix, serving, permission.method);
  return `<http|https>://${hostPart(serving.hosts)}${prefix}${path}${extent}`;
};

/**
 * A declared type the path binds an id for becomes a check on that resource,
 * addressed by its resource name — the deployment's key for the real thing; an
 * operation binding none is checked against the service singleton. Every
 * declared type, bound or not, is asked for in `scope` under both spellings:
 * the resource name is what the grants hold, the type is what the caller's
 * service reads back in X-Scope.
 */
const payloadFor = (permission: Permission, service: string): string => {
  const check = (object: string) =>
    `{"namespace":"${ketoNamespace(service)}","object":"${object}","relation":"${permission.name}","subject_id":"{{ print .Subject }}"}`;

  const checks = permission.scopedBy
    .filter((r) => r.captureIndex !== undefined)
    .map((r) => check(`${r.resourceName}/{{ printIndex .MatchContext.RegexpCaptureGroups ${r.captureIndex} }}`));

  const body = checks.length === 0 ? check('__self__') : checks.length === 1 ? checks[0]! : `{"allOf":[${checks.join(',')}]}`;

  const scope = permission.scopedBy
    .map((r) => `{"type":"${r.type}","resourceName":"${r.resourceName}"}`)
    .join(',');
  return `${body.slice(0, -1)},"scope":[${scope}]}`;
};

const rule = (
  permission: Permission,
  bundle: ServiceBundle,
  allPaths: string[],
  serving: Serving,
): unknown => {
  return {
    id: permission.id,
    match: { url: matchUrl(permission, bundle, allPaths, serving), methods: [permission.method] },
    authenticators: (serving.authenticators ?? AUTHENTICATORS).map((handler) => ({ handler })),
    authorizer: {
      handler: 'remote_json',
      config: { payload: payloadFor(permission, bundle.service) },
    },
    mutators: [{ handler: 'noop' }],
  };
};

/** CORS preflights carry no credentials and are answered before authorization. */
const preflight = (bundle: ServiceBundle, serving: Serving): unknown => {
  const prefix = prefixOf(bundle, serving);
  return {
    id: `${bundle.service}.preflight`,
    match: { url: `<http|https>://${hostPart(serving.hosts)}${prefix}${subtree(prefix, serving)}`, methods: ['OPTIONS'] },
    authenticators: [{ handler: 'noop' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  };
};

export function emitRules(bundle: ServiceBundle, serving: Serving = {}): unknown[] {
  const allPaths = [...new Set(bundle.permissions.map((p) => p.path))];
  return [preflight(bundle, serving), ...bundle.permissions.map((p) => rule(p, bundle, allPaths, serving))];
}
