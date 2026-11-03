import { Mount, MountType, Rewrite } from '../authzgen/emit-rules';
import { describeObject, ObjectRef, Problem, refOf, sameObject } from '../authzgen/problem';

/**
 * Reading HTTPRoutes: which backends a route opts in, what name each answers
 * under, where each one's document comes from, and which rules reach it.
 *
 * Everything that decides identity sits on the route, which the deployment
 * writes and every app already has. Annotations are keyed by the name the
 * route's own backendRefs give a backend, so a route is read as it is and
 * nothing in its spec is asked to change.
 */

export const ANNOTATION_PREFIX = 'iam.mojaloop.io/';

/** An annotation name is at most 63 characters after its prefix. */
const MAX_KEY = 63;
const Setting = { service: 'service', schema: 'schema' } as const;
type Setting = (typeof Setting)[keyof typeof Setting];
const SETTINGS: readonly string[] = Object.values(Setting);

/** The Gateway API words a route is read by. */
const CORE_GROUP = 'core';
const SERVICE_KIND = 'Service';
export const GATEWAY_KIND = 'Gateway';
const FilterType = { externalAuth: 'ExternalAuth', urlRewrite: 'URLRewrite' } as const;
const REPLACE_PREFIX_MATCH = 'ReplacePrefixMatch';
const ROOT_PATH = '/';

/** A route rule's place, as a message names it. */
const ruleOf = (route: ObjectRef, index: number): string => `HTTPRoute/${describeObject(route)} rule ${index + 1}`;

export interface RouteMatch {
  path?: { type?: string; value?: string };
  method?: string;
}

export interface RouteFilter {
  type?: string;
  urlRewrite?: { path?: { type?: string; replacePrefixMatch?: string; replaceFullPath?: string } };
}

export interface BackendReference {
  group?: string;
  kind?: string;
  name?: string;
  namespace?: string;
  port?: number;
  weight?: number;
}

export interface RouteRule {
  matches?: RouteMatch[];
  filters?: RouteFilter[];
  backendRefs?: BackendReference[];
}

export interface HTTPRouteResource {
  metadata?: { name?: string; namespace?: string; annotations?: Record<string, string> };
  spec?: {
    hostnames?: string[];
    parentRefs?: Array<{ name?: string; namespace?: string; sectionName?: string; kind?: string; group?: string }>;
    rules?: RouteRule[];
  };
}

/** One rule's share of what a backend answers: which requests reach it and how their path is rewritten. */
export interface Reach {
  matches: Mount[];
  rewrite?: Rewrite;
}

export interface KeyedBackend {
  /** The route keying it. */
  route: ObjectRef;
  /** The Service the route sends traffic to. */
  backend: ObjectRef;
  port: number;
  /** The prefix of this backend's permissions. */
  service: string;
  /** The AuthzDocument in the route's namespace that is this backend's document. */
  schema?: ObjectRef;
  hosts: string[];
  reaches: Reach[];
}

export interface ReadRoute {
  backends: KeyedBackend[];
  /** Why part of this route is not composed. */
  problems: Problem[];
  /** Keyed backends behind a rule that never asks the platform: loud, and not blocking. */
  unenforced: Problem[];
}

const isServiceRef = (ref: BackendReference): boolean =>
  (ref.group === undefined || ref.group === '' || ref.group === CORE_GROUP) && (ref.kind === undefined || ref.kind === SERVICE_KIND);

const asksPlatform = (rule: RouteRule): boolean => (rule.filters ?? []).some((f) => f.type === FilterType.externalAuth);

const isMountType = (type: string): type is MountType => (Object.values(MountType) as string[]).includes(type);

/**
 * Reads one route. `listenerHosts` answers the hostnames a route without its
 * own inherits from the listeners it attaches to.
 */
export function readRoute(route: HTTPRouteResource, listenerHosts: string[] = []): ReadRoute {
  const ref = refOf(route.metadata);
  const id = describeObject(ref);
  const messages: string[] = [];
  const unenforcedMessages: string[] = [];
  const about = (list: string[]): Problem[] => list.map((message) => ({ message, routes: [ref] }));
  const read = (backends: KeyedBackend[]): ReadRoute => ({ backends, problems: about(messages), unenforced: about(unenforcedMessages) });

  const keys = new Map<string, Partial<Record<Setting, string>>>();
  for (const [key, value] of Object.entries(route.metadata?.annotations ?? {})) {
    if (!key.startsWith(ANNOTATION_PREFIX)) continue;
    const rest = key.slice(ANNOTATION_PREFIX.length);
    const dot = rest.lastIndexOf('.');
    const setting = rest.slice(dot + 1);
    if (dot <= 0 || !SETTINGS.includes(setting)) {
      messages.push(`HTTPRoute/${id}: ${key} is not <backend>.${Setting.service} or <backend>.${Setting.schema}`);
      continue;
    }
    const backend = rest.slice(0, dot);
    keys.set(backend, { ...keys.get(backend), [setting as Setting]: value });
  }
  if (keys.size === 0) return read([]);

  const rules = route.spec?.rules ?? [];
  const refs = rules.flatMap((rule) => (rule.backendRefs ?? []).filter(isServiceRef));

  const namespacesOf = new Map<string, Set<string>>();
  for (const backendRef of refs) {
    if (backendRef.name === undefined) continue;
    const namespaces = namespacesOf.get(backendRef.name) ?? new Set<string>();
    namespaces.add(backendRef.namespace ?? ref.namespace);
    namespacesOf.set(backendRef.name, namespaces);
  }

  for (const [backend, settings] of keys) {
    if (!namespacesOf.has(backend)) {
      messages.push(`HTTPRoute/${id}: ${ANNOTATION_PREFIX}${backend}.* names no backend of this route`);
    } else if (settings.service === undefined) {
      messages.push(`HTTPRoute/${id}: ${backend} has a ${Setting.schema} but no ${ANNOTATION_PREFIX}${backend}.${Setting.service}`);
    }
  }
  for (const [name, namespaces] of namespacesOf) {
    if (namespaces.size > 1) {
      messages.push(`HTTPRoute/${id}: backend ${name} is referenced in ${[...namespaces].sort().join(' and ')}, which its key cannot tell apart`);
    } else if (!keys.get(name)?.service) {
      messages.push(
        name.length + 1 + Setting.service.length > MAX_KEY
          ? `HTTPRoute/${id}: backend ${name} is too long to key; nothing it answers is authorized`
          : `HTTPRoute/${id}: backend ${name} has no ${ANNOTATION_PREFIX}${name}.${Setting.service}; nothing it answers is authorized`,
      );
    }
  }

  const hosts = route.spec?.hostnames?.length ? route.spec.hostnames : listenerHosts;
  if (hosts.length === 0) {
    messages.push(`HTTPRoute/${id}: names no hostname and its listeners declare none`);
    return read([]);
  }

  const found: KeyedBackend[] = [];
  rules.forEach((rule, index) => {
    const live = (rule.backendRefs ?? []).filter((r) => isServiceRef(r) && r.weight !== 0 && r.name !== undefined);
    const keyed = live.filter((r) => keys.get(r.name!)?.service !== undefined && namespacesOf.get(r.name!)!.size === 1);
    if (keyed.length === 0) return;

    const where = ruleOf(ref, index);
    if (live.length > 1) {
      // Authorization runs before the backend is chosen, so a request here
      // would need every backend's permission at once.
      messages.push(`${where}: splits traffic across ${live.map((r) => r.name).join(', ')}, which is refused`);
      return;
    }

    const matches: Reach['matches'] = [];
    let readable = true;
    for (const match of rule.matches?.length ? rule.matches : [{}]) {
      const type = match.path?.type ?? MountType.prefix;
      if (!isMountType(type)) {
        messages.push(`${where}: a ${type} path match cannot be read as a set of operations`);
        readable = false;
        break;
      }
      matches.push({ type, path: match.path?.value ?? ROOT_PATH, ...(match.method ? { method: match.method } : {}) });
    }

    let rewrite: Rewrite | undefined;
    for (const filter of rule.filters ?? []) {
      if (filter.type !== FilterType.urlRewrite || filter.urlRewrite?.path === undefined) continue;
      const replaced = filter.urlRewrite.path;
      const prefixes = [...new Set(matches.map((m) => m.path))];
      if (replaced.type !== REPLACE_PREFIX_MATCH || replaced.replacePrefixMatch === undefined || prefixes.length !== 1) {
        messages.push(`${where}: this ${FilterType.urlRewrite} cannot be mapped back to the paths clients send`);
        readable = false;
        break;
      }
      rewrite = { from: prefixes[0]!, to: replaced.replacePrefixMatch };
    }
    if (!readable) return;

    const chosen = keyed[0]!;
    if (!asksPlatform(rule)) {
      unenforcedMessages.push(`${where}: sends ${chosen.name} requests without the ${FilterType.externalAuth} filter`);
    }
    if (chosen.port === undefined) {
      messages.push(`${where}: backend ${chosen.name} names no port`);
      return;
    }

    const target: ObjectRef = { namespace: chosen.namespace ?? ref.namespace, name: chosen.name! };
    const settings = keys.get(target.name)!;
    let backend = found.find((b) => sameObject(b.backend, target) && b.port === chosen.port);
    if (backend === undefined) {
      backend = {
        route: ref,
        backend: target,
        port: chosen.port,
        service: settings.service!,
        ...(settings.schema !== undefined ? { schema: { namespace: ref.namespace, name: settings.schema } } : {}),
        hosts: [...hosts],
        reaches: [],
      };
      found.push(backend);
    }
    backend.reaches.push({ matches, ...(rewrite !== undefined ? { rewrite } : {}) });
  });

  return read(found);
}

/** A path prefix a rule answers on its route's hosts, whoever it sends the traffic to. */
export interface Claim {
  hosts: string[];
  path: string;
}

/**
 * Every prefix a route's rules answer, keyed or not. A rule owning a subtree
 * gives these up, since otherwise its permission would admit requests another
 * backend serves.
 */
export function claimsOf(route: HTTPRouteResource, listenerHosts: string[] = []): Claim[] {
  const hosts = route.spec?.hostnames?.length ? route.spec.hostnames : listenerHosts;
  return (route.spec?.rules ?? []).flatMap((rule) =>
    (rule.matches?.length ? rule.matches : [{}]).map((match) => ({ hosts, path: match.path?.value ?? ROOT_PATH })),
  );
}

/** A Gateway API hostname matching any one leading label. */
const WILDCARD_LABEL = '*.';
const LABEL_SEPARATOR = '.';

/** Whether two host lists can name the same request host. */
export const hostsMeet = (a: string[], b: string[]): boolean =>
  a.some((x) =>
    b.some((y) => {
      if (x === y) return true;
      const wild = (w: string, h: string) =>
        w.startsWith(WILDCARD_LABEL) && h.endsWith(w.slice(1)) && !h.slice(0, -w.length + 1).includes(LABEL_SEPARATOR);
      return wild(x, y) || wild(y, x);
    }),
  );

/** Whether a client request for this method and path template is sent through this reach. */
export const reaches = (reach: Reach, method: string, path: string): boolean =>
  reach.matches.some((match) => {
    if (match.method !== undefined && match.method.toUpperCase() !== method.toUpperCase()) return false;
    if (match.type === MountType.exact) return path === match.path;
    const prefix = match.path.replace(/\/+$/, '');
    return prefix === '' || path === prefix || path.startsWith(`${prefix}/`);
  });
