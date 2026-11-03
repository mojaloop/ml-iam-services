import { accessRules, ResourceNames } from '../authzgen/compose';
import { concernsObject, describeObject, messagesOf, ObjectRef, Problem, refOf, sameObject } from '../authzgen/problem';
import { Reason, Verdict } from '../iam/conditions';
import { Kind } from '../iam/kinds';
import { claimNames, DeploymentObject, idOf, resourceNamesOf, writeStatus } from '../iam/objects';
import type { ResourceCount } from '../iam/provisioner';
import { Logged } from '../logged';
import {
  AuthzDocument,
  AuthzResourceName,
  Gateway,
  listDocuments,
  listGateways,
  listResourceNames,
  listRoutes,
  publish,
  reportOnRoute,
  setStatus,
  watchBackends,
  watchInputs,
} from './cluster';
import { Declared, reconcile, Reconciled } from './reconcile';
import { Claim, claimsOf, GATEWAY_KIND, hostsMeet, HTTPRouteResource, KeyedBackend, readRoute } from './routes';
import { AuthzDocumentResource, fromResource, ServedDocuments } from './sources';

/** The files the gateway and Keto mount from the published ConfigMap. */
export const PublishedFile = { accessRules: 'access-rules.yml', ketoNamespaces: 'keto-namespaces.ts' } as const;

const ALREADY_RUNNING: Problem = { message: 'a reconcile is already running' };
const NO_ROUTE = 'no route names it';

/**
 * Reads the deployment's routes, the documents their backends serve or name,
 * and the resource names the deployment declares, and publishes the
 * composition. A prefix with a problem keeps its last good rules while
 * everything else moves on.
 */

export interface OperatorOptions {
  /** The namespace the published files live in. */
  namespace: string;
  /** The ConfigMap the gateway and Keto read. */
  publishAs?: string;
  /** Called with each accepted composition and the resource names it was composed against. */
  onAccepted?: (result: Reconciled, names: ResourceNames) => void | Promise<void>;
  /** Whether this replica leads: one that does not composes for itself and writes nothing back. */
  leading?: () => boolean;
  /** A resource name's figures read now, against the names just composed, so a source declared wrong is refused when its object changes. */
  count?: (resourceName: string, names: ResourceNames) => Promise<ResourceCount>;
  /** The IAM's own prefix. */
  servesAs?: string;
}

/** The hostnames the listeners a route attaches to declare, for a route that names none. */
const listenerHostsOf = (route: HTTPRouteResource, gateways: Gateway[]): string[] => {
  const routeNamespace = refOf(route.metadata).namespace;
  return (route.spec?.parentRefs ?? [])
    .filter((ref) => (ref.kind ?? GATEWAY_KIND) === GATEWAY_KIND)
    .flatMap((ref) => {
      const gateway = gateways.find(
        (g) => g.metadata?.name === ref.name && g.metadata?.namespace === (ref.namespace ?? routeNamespace),
      );
      return (gateway?.spec?.listeners ?? [])
        .filter((listener) => ref.sectionName === undefined || listener.name === ref.sectionName)
        .flatMap((listener) => (listener.hostname !== undefined ? [listener.hostname] : []));
    });
};

export class Operator {
  private readonly options: OperatorOptions;
  private readonly served = new ServedDocuments();
  private accepted?: Reconciled;
  private watcher?: { close: () => void };
  private rollouts?: { close: () => void };
  /** The Services whose documents the last pass read. */
  private backends: ObjectRef[] = [];
  /** The routes keying each service. */
  private routesOf = new Map<string, ObjectRef[]>();
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
    this.watcher = await watchInputs(async () => this.schedule());
    this.rollouts = await watchBackends(
      (service) => concernsObject(this.backends, service),
      async () => this.schedule(),
    );
    return first;
  }

  private schedule(): void {
    this.run().catch((error) => console.error(JSON.stringify({ event: Logged.reconcileFailed, error: String(error) })));
  }

  stop(): void {
    this.watcher?.close();
    this.rollouts?.close();
  }

  /** Says something about a service on every route keying it, where the route's owner looks. */
  async announceChange(service: string, message: string): Promise<void> {
    for (const route of this.routesOf.get(service) ?? []) {
      await reportOnRoute(route.namespace, route.name, message).catch((error) =>
        console.error(JSON.stringify({ event: Logged.routeReportFailed, route: describeObject(route), error: String(error) })),
      );
    }
  }

  /**
   * One pass. Overlapping calls collapse into one more pass afterwards, so a
   * burst of changes composes once, from the set they settle at.
   */
  async run(): Promise<Reconciled> {
    if (this.running) {
      this.again = true;
      return this.accepted ?? { problems: [ALREADY_RUNNING], held: [], origins: [], services: {} };
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
    const [routes, resources, gateways, nameObjects] = await Promise.all([
      listRoutes(),
      listDocuments(),
      listGateways(),
      listResourceNames(),
    ]);
    const claimed = claimNames(Kind.resourceName, nameObjects);
    const names = resourceNamesOf(claimed.owners);

    const backends: KeyedBackend[] = [];
    const claims: Claim[] = [];
    const routeProblems: Problem[] = [];
    const unenforced: Problem[] = [];
    for (const route of routes) {
      const hosts = listenerHostsOf(route, gateways);
      claims.push(...claimsOf(route, hosts));
      const read = readRoute(route, hosts);
      backends.push(...read.backends);
      routeProblems.push(...read.problems);
      unenforced.push(...read.unenforced);
    }
    this.backends = backends.filter((b) => b.schema === undefined).map((b) => b.backend);
    this.routesOf = new Map();
    for (const backend of backends) {
      const keying = this.routesOf.get(backend.service) ?? [];
      if (!concernsObject(keying, backend.route)) keying.push(backend.route);
      this.routesOf.set(backend.service, keying);
    }

    const declared: Declared[] = await Promise.all(
      backends.map(async (backend): Promise<Declared> => {
        const origin = `HTTPRoute/${describeObject(backend.route)} → ${describeObject(backend.backend)}`;
        const own = new Set(backend.reaches.flatMap((r) => r.matches.map((m) => m.path)));
        const exclude = claims
          .filter((claim) => hostsMeet(claim.hosts, backend.hosts) && !own.has(claim.path))
          .map((claim) => claim.path);
        const url = ServedDocuments.urlOf(backend.backend, backend.port);
        const base = {
          origin,
          service: backend.service,
          route: backend.route,
          backend: backend.backend,
          source: backend.schema === undefined ? { url } : { schema: backend.schema },
          hosts: backend.hosts,
          reaches: backend.reaches,
          exclude,
        };
        try {
          if (backend.schema === undefined) {
            return { ...base, document: await this.served.read(url) };
          }
          const schema = backend.schema;
          const resource = resources.find((r) => sameObject(refOf(r.metadata), schema));
          if (resource === undefined) return { ...base, problem: `no AuthzDocument ${describeObject(schema)}` };
          return { ...base, document: await fromResource(resource) };
        } catch (error) {
          return { ...base, problem: (error as Error).message };
        }
      }),
    );

    const result = reconcile(declared, names, { services: this.accepted?.services }, this.options.servesAs);
    const problems = [...routeProblems, ...result.problems];
    const reported = { ...result, problems };
    const writes = this.options.leading?.() ?? true;

    if (writes) {
      await this.report(routes, [...problems, ...unenforced]);
      await this.tell(resources, backends, reported);
      await this.tellNames(nameObjects, claimed.refused, reported, names);
    }
    console.log(
      JSON.stringify({
        event: Logged.reconciled,
        held: result.held,
        problems: messagesOf(problems),
        unenforced: messagesOf(unenforced),
        unbound: messagesOf(result.composition?.unbound ?? []),
      }),
    );

    if (result.composition === undefined) return reported;

    this.accepted = reported;
    if (writes && this.options.publishAs !== undefined) {
      // Only what another pod mounts as a file. A ConfigMap holds a megabyte,
      // and the catalog, the derivation and the per-service rules are served
      // over the API by the process that composed them.
      await publish(this.options.namespace, this.options.publishAs, {
        [PublishedFile.accessRules]: accessRules(result.composition.rules),
        [PublishedFile.ketoNamespaces]: result.composition.model,
      });
    }
    await this.options.onAccepted?.(reported, names);
    return reported;
  }

  /** Puts every problem on the routes it concerns, where each route's owner looks. */
  private async report(routes: HTTPRouteResource[], problems: Problem[]): Promise<void> {
    for (const route of routes) {
      const ref = refOf(route.metadata);
      for (const problem of problems.filter((p) => concernsObject(p.routes, ref))) {
        await reportOnRoute(ref.namespace, ref.name, problem.message).catch(() => undefined);
      }
    }
  }

  /** Writes each document's fate back onto it. */
  private async tell(resources: AuthzDocumentResource[], backends: KeyedBackend[], result: Reconciled): Promise<void> {
    for (const resource of resources) {
      const ref = refOf(resource.metadata);
      const readers = backends.filter((b) => b.schema !== undefined && sameObject(b.schema, ref));
      const services = [...new Set(readers.map((b) => b.service))].sort();
      const concerning = result.problems.filter(
        (p) => concernsObject(p.documents, ref) || (p.services ?? []).some((s) => services.includes(s)),
      );
      const verdict: Verdict =
        concerning.length > 0
          ? { reason: Reason.refused, message: messagesOf(concerning).join('; ') }
          : readers.length === 0
            ? { reason: Reason.waiting, message: NO_ROUTE }
            : { reason: Reason.accepted, message: `read as ${services.join(', ')}` };
      await this.status(AuthzDocument, resource as DeploymentObject, verdict, {});
    }
  }

  /** Writes each resource name's fate back onto it: refused, waiting for the services it lists, or bound. */
  private async tellNames(
    objects: AuthzResourceName[],
    duplicates: Map<AuthzResourceName, string>,
    result: Reconciled,
    names: ResourceNames,
  ): Promise<void> {
    const unbound = result.composition?.unbound ?? [];
    for (const object of objects) {
      const name = object.metadata?.name ?? '';
      const mentions = (problem: Problem) => problem.resourceNames?.includes(name) ?? false;
      const problems = messagesOf(result.problems.filter(mentions));
      const waiting = messagesOf(unbound.filter(mentions));
      const members = object.spec?.members?.length ?? 0;
      const listed = object.spec?.source !== undefined ? await this.options.count?.(name, names) : undefined;
      const unread = listed?.failed !== undefined && listed.misdeclared !== true ? [`its source did not answer: ${listed.failed}`] : [];
      const verdict: Verdict = duplicates.has(object)
        ? { reason: Reason.refused, message: duplicates.get(object)! }
        : problems.length > 0
          ? { reason: Reason.refused, message: problems.join('; ') }
          : listed?.misdeclared === true
            ? { reason: Reason.refused, message: listed.failed! }
            : waiting.length === members && members > 0
              ? { reason: Reason.waiting, message: [...waiting, ...unread].join('; ') }
              : {
                reason: Reason.accepted,
                message: [`${members - waiting.length} of ${members} members bound`, ...waiting, ...unread].join('; '),
              };
      await this.status(AuthzResourceName, object, verdict, {});
    }
  }

  private async status(
    model: typeof AuthzDocument | typeof AuthzResourceName,
    object: DeploymentObject,
    verdict: Verdict,
    fields: Record<string, unknown>,
  ): Promise<void> {
    await writeStatus(object, verdict, fields, (namespace, name, status) => setStatus(model, namespace, name, status)).catch(
      (error) =>
        console.error(
          JSON.stringify({ event: Logged.statusFailed, object: idOf(model.name, object), error: String(error) }),
        ),
    );
  }
}

export type { AuthzDocument };
