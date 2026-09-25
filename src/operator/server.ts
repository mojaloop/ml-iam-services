import { accessRules, Migrations, ResourceNames } from '../authzgen/compose';
import {
  AuthzDocument,
  Gateway,
  listDocuments,
  listGateways,
  listRoutes,
  publish,
  reportOn,
  reportOnRoute,
  watchInputs,
} from './cluster';
import { Declared, reconcile, Reconciled } from './reconcile';
import { Claim, claimsOf, hostsMeet, HTTPRouteResource, KeyedBackend, readRoute } from './routes';
import { AuthzDocumentResource, documentId, fromResource, ServedDocuments } from './sources';

/**
 * Reads the deployment's routes, the documents their backends serve or name,
 * and publishes the composition. A prefix with a problem keeps its last good
 * rules while everything else moves on.
 */

export interface OperatorOptions {
  /** The namespace the published files live in. */
  namespace: string;
  /** What the deployment says its services' vocabularies have in common. */
  names?: ResourceNames;
  /** Where the grants of a removed or changed permission go. */
  migrations?: Migrations;
  /** The ConfigMap the gateway and Keto read. */
  publishAs?: string;
  /** How often served documents are read again, since a rollout changes them without touching a route. */
  refreshMs?: number;
  /** Called with each accepted composition, for the IAM to serve. */
  onAccepted?: (result: Reconciled) => void | Promise<void>;
}

const REFRESH_MS = 30_000;

/** The hostnames the listeners a route attaches to declare, for a route that names none. */
const listenerHostsOf = (route: HTTPRouteResource, gateways: Gateway[]): string[] => {
  const routeNamespace = route.metadata?.namespace ?? 'default';
  return (route.spec?.parentRefs ?? [])
    .filter((ref) => (ref.kind ?? 'Gateway') === 'Gateway')
    .flatMap((ref) => {
      const gateway = gateways.find(
        (g) => g.metadata?.name === ref.name && g.metadata?.namespace === (ref.namespace ?? routeNamespace),
      );
      return (gateway?.spec?.listeners ?? [])
        .filter((listener) => ref.sectionName === undefined || listener.name === ref.sectionName)
        .flatMap((listener) => (listener.hostname !== undefined ? [listener.hostname] : []));
    });
};

const routeName = (route: HTTPRouteResource) => ({
  namespace: route.metadata?.namespace ?? 'default',
  name: route.metadata?.name ?? '(unnamed)',
});

export class Operator {
  private readonly options: OperatorOptions;
  private readonly served = new ServedDocuments();
  private accepted?: Reconciled;
  private watcher?: { close: () => void };
  private timer?: NodeJS.Timeout;
  private running = false;
  private again = false;

  constructor(options: OperatorOptions) {
    this.options = options;
  }

  /** What the platform is currently serving, or nothing if it never accepted one. */
  get composition(): Reconciled | undefined {
    return this.accepted;
  }

  async start(): Promise<Reconciled> {
    const first = await this.run();
    this.watcher = await watchInputs(async () => {
      await this.run();
    });
    this.timer = setInterval(() => void this.run(), this.options.refreshMs ?? REFRESH_MS);
    return first;
  }

  stop(): void {
    this.watcher?.close();
    if (this.timer !== undefined) clearInterval(this.timer);
  }

  /**
   * One pass. Overlapping calls collapse into one more pass afterwards, so a
   * burst of changes composes once, from the set they settle at.
   */
  async run(): Promise<Reconciled> {
    if (this.running) {
      this.again = true;
      return this.accepted ?? { problems: ['a reconcile is already running'], held: [], origins: [], services: {} };
    }

    this.running = true;
    try {
      return await this.pass();
    } finally {
      this.running = false;
      if (this.again) {
        this.again = false;
        await this.run();
      }
    }
  }

  private async pass(): Promise<Reconciled> {
    const [routes, resources, gateways] = await Promise.all([listRoutes(), listDocuments(), listGateways()]);
    const byId = new Map(resources.map((r) => [documentId(r), r]));

    const backends: KeyedBackend[] = [];
    const claims: Claim[] = [];
    const routeProblems: string[] = [];
    const unenforced: string[] = [];
    for (const route of routes) {
      const hosts = listenerHostsOf(route, gateways);
      claims.push(...claimsOf(route, hosts));
      const read = readRoute(route, hosts);
      backends.push(...read.backends);
      routeProblems.push(...read.problems);
      unenforced.push(...read.unenforced);
    }

    const refused = new Map<string, string>();
    const declared: Declared[] = await Promise.all(
      backends.map(async (backend): Promise<Declared> => {
        const origin = `HTTPRoute/${backend.route} → ${backend.namespace}/${backend.name}`;
        const own = new Set(backend.reaches.flatMap((r) => r.matches.map((m) => m.path)));
        const exclude = claims
          .filter((claim) => hostsMeet(claim.hosts, backend.hosts) && !own.has(claim.path))
          .map((claim) => claim.path);
        const url = ServedDocuments.urlOf(backend.namespace, backend.name, backend.port);
        const base = {
          origin,
          service: backend.service,
          backend: `${backend.namespace}/${backend.name}`,
          source: backend.schema === undefined ? url : `AuthzDocument/${backend.routeNamespace}/${backend.schema}`,
          hosts: backend.hosts,
          reaches: backend.reaches,
          exclude,
        };
        try {
          if (backend.schema === undefined) {
            return { ...base, document: await this.served.read(url) };
          }
          const id = `${backend.routeNamespace}/${backend.schema}`;
          const resource = byId.get(id);
          if (resource === undefined) return { ...base, problem: `no AuthzDocument ${id}` };
          return { ...base, document: await fromResource(resource) };
        } catch (error) {
          if (backend.schema !== undefined) refused.set(`${backend.routeNamespace}/${backend.schema}`, (error as Error).message);
          return { ...base, problem: (error as Error).message };
        }
      }),
    );

    const result = reconcile(
      declared,
      this.options.names ?? {},
      { catalog: this.accepted?.composition?.catalog, services: this.accepted?.services },
      this.options.migrations ?? {},
    );
    const problems = [...routeProblems, ...result.problems];
    const reported = { ...result, problems };

    await this.report(routes, [...problems, ...unenforced]);
    await this.tell(resources, backends, refused, reported);
    console.log(
      JSON.stringify({
        event: 'reconciled',
        held: result.held,
        problems,
        unenforced,
        unbound: result.composition?.unbound ?? [],
      }),
    );

    if (result.composition === undefined) return reported;

    this.accepted = reported;
    if (this.options.publishAs !== undefined) {
      // Only what another pod mounts as a file. A ConfigMap holds a megabyte,
      // and the catalog, the derivation and the per-service rules are served
      // over the API by the process that composed them.
      await publish(this.options.namespace, this.options.publishAs, {
        'access-rules.yml': accessRules(result.composition.rules),
        'keto-namespaces.ts': result.composition.model,
      });
    }
    await this.options.onAccepted?.(reported);
    return reported;
  }

  /** Puts every problem on the route it names, where the route's owner looks. */
  private async report(routes: HTTPRouteResource[], messages: string[]): Promise<void> {
    for (const route of routes) {
      const { namespace, name } = routeName(route);
      const id = `HTTPRoute/${namespace}/${name}`;
      for (const message of messages.filter((m) => m.includes(`${id} `) || m.includes(`${id}:`))) {
        await reportOnRoute(namespace, name, message).catch(() => undefined);
      }
    }
  }

  /** Writes each document's fate back onto it. */
  private async tell(
    resources: AuthzDocumentResource[],
    backends: KeyedBackend[],
    refused: Map<string, string>,
    result: Reconciled,
  ): Promise<void> {
    for (const resource of resources) {
      const id = documentId(resource);
      const namespace = resource.metadata?.namespace;
      const name = resource.metadata?.name;
      if (namespace === undefined || name === undefined) continue;

      const readers = backends.filter((b) => `${b.routeNamespace}/${b.schema}` === id);
      const services = [...new Set(readers.map((b) => b.service))].sort();
      const failure = refused.get(id);
      const held = services.some((s) => result.held.includes(s));
      const state =
        failure !== undefined || held ? 'Refused' : readers.length === 0 ? 'Unreferenced' : 'Accepted';
      const messages =
        failure !== undefined
          ? [failure]
          : held
            ? result.problems.filter((p) => services.some((s) => p.startsWith(`${s} `) || p.includes(`AuthzDocument/${id}`)))
            : [];

      await reportOn(namespace, name, {
        state,
        ...(services.length > 0 ? { service: services.join(',') } : {}),
        messages,
        ...(resource.metadata?.generation !== undefined ? { observedGeneration: resource.metadata.generation } : {}),
      }).catch(() => undefined);
    }
  }
}

export type { AuthzDocument };
