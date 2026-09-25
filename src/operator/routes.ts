import { Mount, Rewrite } from '../authzgen/emit-rules';

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
const SETTINGS = ['service', 'schema'] as const;
type Setting = (typeof SETTINGS)[number];

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
  /** `<namespace>/<name>` of the route. */
  route: string;
  routeNamespace: string;
  /** The Service the route sends traffic to. */
  namespace: string;
  name: string;
  port: number;
  /** The prefix of this backend's permissions. */
  service: string;
  /** The AuthzDocument in the route's namespace that is this backend's document. */
  schema?: string;
  hosts: string[];
  reaches: Reach[];
}

export interface ReadRoute {
  backends: KeyedBackend[];
  /** Why part of this route is not composed; each already names the route. */
  problems: string[];
  /** Keyed backends behind a rule that never asks the platform: loud, and not blocking. */
  unenforced: string[];
}

const isServiceRef = (ref: BackendReference): boolean =>
  (ref.group === undefined || ref.group === '' || ref.group === 'core') && (ref.kind === undefined || ref.kind === 'Service');

const asksPlatform = (rule: RouteRule): boolean => (rule.filters ?? []).some((f) => f.type === 'ExternalAuth');

/**
 * Reads one route. `listenerHosts` answers the hostnames a route without its
 * own inherits from the listeners it attaches to.
 */
export function readRoute(route: HTTPRouteResource, listenerHosts: string[] = []): ReadRoute {
  const routeNamespace = route.metadata?.namespace ?? 'default';
  const id = `${routeNamespace}/${route.metadata?.name ?? '(unnamed)'}`;
  const problems: string[] = [];
  const unenforced: string[] = [];

  const keys = new Map<string, Partial<Record<Setting, string>>>();
  for (const [key, value] of Object.entries(route.metadata?.annotations ?? {})) {
    if (!key.startsWith(ANNOTATION_PREFIX)) continue;
    const rest = key.slice(ANNOTATION_PREFIX.length);
    const dot = rest.lastIndexOf('.');
    const setting = rest.slice(dot + 1) as Setting;
    if (dot <= 0 || !SETTINGS.includes(setting)) {
      problems.push(`HTTPRoute/${id}: ${key} is not <backend>.service or <backend>.schema`);
      continue;
    }
    const backend = rest.slice(0, dot);
    keys.set(backend, { ...keys.get(backend), [setting]: value });
  }
  if (keys.size === 0) return { backends: [], problems, unenforced };

  const rules = route.spec?.rules ?? [];
  const refs = rules.flatMap((rule) => (rule.backendRefs ?? []).filter(isServiceRef));

  const namespacesOf = new Map<string, Set<string>>();
  for (const ref of refs) {
    if (ref.name === undefined) continue;
    const namespaces = namespacesOf.get(ref.name) ?? new Set<string>();
    namespaces.add(ref.namespace ?? routeNamespace);
    namespacesOf.set(ref.name, namespaces);
  }

  for (const [backend, settings] of keys) {
    if (!namespacesOf.has(backend)) {
      problems.push(`HTTPRoute/${id}: ${ANNOTATION_PREFIX}${backend}.* names no backend of this route`);
    } else if (settings.service === undefined) {
      problems.push(`HTTPRoute/${id}: ${backend} has a schema but no ${ANNOTATION_PREFIX}${backend}.service`);
    }
  }
  for (const [name, namespaces] of namespacesOf) {
    if (namespaces.size > 1) {
      problems.push(`HTTPRoute/${id}: backend ${name} is referenced in ${[...namespaces].sort().join(' and ')}, which its key cannot tell apart`);
    } else if (!keys.get(name)?.service) {
      problems.push(
        name.length + '.service'.length > MAX_KEY
          ? `HTTPRoute/${id}: backend ${name} is too long to key; nothing it answers is authorized`
          : `HTTPRoute/${id}: backend ${name} has no ${ANNOTATION_PREFIX}${name}.service; nothing it answers is authorized`,
      );
    }
  }

  const hosts = route.spec?.hostnames?.length ? route.spec.hostnames : listenerHosts;
  if (hosts.length === 0) {
    problems.push(`HTTPRoute/${id}: names no hostname and its listeners declare none`);
    return { backends: [], problems, unenforced };
  }

  const found = new Map<string, KeyedBackend>();
  rules.forEach((rule, index) => {
    const live = (rule.backendRefs ?? []).filter((ref) => isServiceRef(ref) && ref.weight !== 0 && ref.name !== undefined);
    const keyed = live.filter((ref) => keys.get(ref.name!)?.service !== undefined && namespacesOf.get(ref.name!)!.size === 1);
    if (keyed.length === 0) return;

    const where = `HTTPRoute/${id} rule ${index + 1}`;
    if (live.length > 1) {
      // Authorization runs before the backend is chosen, so a request here
      // would need every backend's permission at once.
      problems.push(`${where}: splits traffic across ${live.map((r) => r.name).join(', ')}, which is refused`);
      return;
    }

    const matches: Reach['matches'] = [];
    let readable = true;
    for (const match of rule.matches?.length ? rule.matches : [{}]) {
      const type = match.path?.type ?? 'PathPrefix';
      if (type !== 'Exact' && type !== 'PathPrefix') {
        problems.push(`${where}: a ${type} path match cannot be read as a set of operations`);
        readable = false;
        break;
      }
      matches.push({ type, path: match.path?.value ?? '/', ...(match.method ? { method: match.method } : {}) });
    }

    let rewrite: Rewrite | undefined;
    for (const filter of rule.filters ?? []) {
      if (filter.type !== 'URLRewrite' || filter.urlRewrite?.path === undefined) continue;
      const replaced = filter.urlRewrite.path;
      const prefixes = [...new Set(matches.map((m) => m.path))];
      if (replaced.type !== 'ReplacePrefixMatch' || replaced.replacePrefixMatch === undefined || prefixes.length !== 1) {
        problems.push(`${where}: this URLRewrite cannot be mapped back to the paths clients send`);
        readable = false;
        break;
      }
      rewrite = { from: prefixes[0]!, to: replaced.replacePrefixMatch };
    }
    if (!readable) return;

    const ref = keyed[0]!;
    if (!asksPlatform(rule)) unenforced.push(`${where}: sends ${ref.name} requests without the ExternalAuth filter`);
    if (ref.port === undefined) {
      problems.push(`${where}: backend ${ref.name} names no port`);
      return;
    }

    const namespace = ref.namespace ?? routeNamespace;
    const settings = keys.get(ref.name!)!;
    const at = `${namespace}/${ref.name}:${ref.port}`;
    const backend = found.get(at) ?? {
      route: id,
      routeNamespace,
      namespace,
      name: ref.name!,
      port: ref.port,
      service: settings.service!,
      ...(settings.schema !== undefined ? { schema: settings.schema } : {}),
      hosts: [...hosts],
      reaches: [],
    };
    backend.reaches.push({ matches, ...(rewrite !== undefined ? { rewrite } : {}) });
    found.set(at, backend);
  });

  return { backends: [...found.values()], problems, unenforced };
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
    (rule.matches?.length ? rule.matches : [{}]).map((match) => ({ hosts, path: match.path?.value ?? '/' })),
  );
}

/** Whether two host lists can name the same request host. */
export const hostsMeet = (a: string[], b: string[]): boolean =>
  a.some((x) =>
    b.some((y) => {
      if (x === y) return true;
      const wild = (w: string, h: string) => w.startsWith('*.') && h.endsWith(w.slice(1)) && !h.slice(0, -w.length + 1).includes('.');
      return wild(x, y) || wild(y, x);
    }),
  );

/** Whether a client request for this method and path template is sent through this reach. */
export const reaches = (reach: Reach, method: string, path: string): boolean =>
  reach.matches.some((match) => {
    if (match.method !== undefined && match.method.toUpperCase() !== method.toUpperCase()) return false;
    if (match.type === 'Exact') return path === match.path;
    const prefix = match.path.replace(/\/+$/, '');
    return prefix === '' || path === prefix || path.startsWith(`${prefix}/`);
  });
