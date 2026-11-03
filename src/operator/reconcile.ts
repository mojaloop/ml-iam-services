import { isDeepStrictEqual } from 'node:util';

import { clientPath, emitCatalog, generate, reachesSubtree, Rewrite } from '../authzgen';
import { compose, ComposedService, Composition, ResourceNames } from '../authzgen/compose';
import { describeObject, ObjectRef, Problem, sameObject } from '../authzgen/problem';
import { Reach, reaches } from './routes';

/**
 * One reading of what the deployment's routes expose.
 *
 * A route keys a backend with the prefix its permissions live under, and that
 * backend's document — served by it, or an AuthzDocument the route names — is
 * the prefix's one source. A prefix keyed on a second Service is two apps
 * under one name, so that prefix is held where it was; every other prefix
 * composes and publishes.
 */

/** Where a backend's document is read: the backend's own URL, or the AuthzDocument its route names. */
export type DocumentSource = { url: string } | { schema: ObjectRef };

const describeSource = (source: DocumentSource): string =>
  'url' in source ? source.url : `AuthzDocument/${describeObject(source.schema)}`;

/** One keyed backend, as one route sends traffic to it. */
export interface Declared {
  /** Where it came from, for a message an operator can act on. */
  origin: string;
  /** The permission prefix the route gives the backend. */
  service: string;
  route: ObjectRef;
  /** The Service: the prefix's one source. */
  backend: ObjectRef;
  source: DocumentSource;
  /** The parsed OpenAPI document, absent when it could not be read. */
  document?: unknown;
  /** Why the document could not be read; the prefix is held. */
  problem?: string;
  hosts: string[];
  reaches: Reach[];
  /** Client path prefixes other rules answer on the same hosts. */
  exclude: string[];
}

export interface Reconciled {
  /** What every prefix together describes, when the prefixes agree with one another. */
  composition?: Composition;
  /** Every problem, held prefixes' included. */
  problems: Problem[];
  /** Prefixes kept at their last composed state because something about them is wrong. */
  held: string[];
  /** Which origins were read. */
  origins: string[];
  /** What each composed prefix was built from, for the next pass to hold. */
  services: Record<string, ComposedService>;
}

const NO_REWRITE = 'none';
const NO_DOCUMENT = 'no document';

const describeRewrite = (rewrite?: Rewrite): string => (rewrite === undefined ? NO_REWRITE : `${rewrite.from}→${rewrite.to}`);

const uniqueBy = <T>(items: T[], same: (a: T, b: T) => boolean): T[] =>
  items.filter((item, at) => items.findIndex((other) => same(item, other)) === at);

const documentOf = (entry: Declared): ObjectRef[] => ('schema' in entry.source ? [entry.source.schema] : []);

/** Composes one prefix, or says why it cannot. */
function composeOne(
  entries: Declared[],
  names: ResourceNames,
  servesAs: string | undefined,
): { service?: ComposedService; problems: Problem[] } {
  const value = entries[0]!.service;
  const origins = uniqueBy(entries, (a, b) => sameObject(a.route, b.route) && sameObject(a.backend, b.backend))
    .map((e) => e.origin)
    .join(', ');
  const about = {
    services: [value],
    routes: uniqueBy(
      entries.map((e) => e.route),
      sameObject,
    ),
    documents: uniqueBy(entries.flatMap(documentOf), sameObject),
  };
  const refused = (message: string) => ({ problems: [{ message, ...about }] });

  const backends = uniqueBy(
    entries.map((e) => e.backend),
    sameObject,
  );
  if (backends.length > 1) {
    return refused(`${origins}: ${value} is keyed on ${backends.map(describeObject).sort().join(' and ')}; a prefix belongs to one Service`);
  }

  const sources = uniqueBy(
    entries.map((e) => e.source),
    isDeepStrictEqual,
  );
  if (sources.length > 1) {
    return refused(`${origins}: ${value} is read from ${sources.map(describeSource).sort().join(' and ')}; a prefix has one document`);
  }

  const byHosts: Array<{ hosts: string[]; mounts: Reach['matches'] }> = [];
  for (const entry of entries) {
    const hosts = [...entry.hosts].sort();
    let group = byHosts.find((g) => isDeepStrictEqual(g.hosts, hosts));
    if (group === undefined) {
      group = { hosts, mounts: [] };
      byHosts.push(group);
    }
    group.mounts = uniqueBy([...group.mounts, ...entry.reaches.flatMap((reach) => reach.matches)], isDeepStrictEqual);
  }
  if (byHosts.some((g) => !isDeepStrictEqual(new Set(g.mounts), new Set(byHosts[0]!.mounts)))) {
    const hosts = byHosts.map((g) => g.hosts.join(',')).sort();
    return refused(`${origins}: ${value} is reached through different paths on ${hosts.join(' and ')}`);
  }

  const unread = entries.filter((e) => e.problem !== undefined || e.document === undefined);
  if (unread.length > 0) {
    return {
      problems: unread.map((e) => ({
        message: `${e.origin}: ${e.problem ?? NO_DOCUMENT}`,
        services: [value],
        routes: [e.route],
        documents: documentOf(e),
      })),
    };
  }

  const reached = entries.flatMap((e) => e.reaches);
  const rewrites = uniqueBy(
    reached.map((r) => r.rewrite),
    isDeepStrictEqual,
  );
  if (rewrites.length > 1) {
    return refused(`${origins}: ${value} is reached through different rewrites (${rewrites.map(describeRewrite).join(', ')})`);
  }
  const rewrite = reached[0]?.rewrite;

  const hosts = [...new Set(entries.flatMap((e) => e.hosts))].sort();
  const own = new Set(reached.flatMap((r) => r.matches.map((m) => m.path.replace(/\/+$/, ''))));
  const exclude = [...new Set(entries.flatMap((e) => e.exclude))].filter((p) => !own.has(p.replace(/\/+$/, '')));

  const within = reached.flatMap((reach) => reach.matches);

  try {
    const result = generate(
      entries[0]!.document,
      value,
      { hosts, ...(rewrite !== undefined ? { rewrite } : {}), exclude, within, caller: value === servesAs },
      names,
      (permission, basePath) => {
        const path = clientPath(`${basePath}${permission.path}`, rewrite);
        if (path === undefined) return false;
        if (permission.path.split('/').filter(Boolean).length === 0) {
          return reachesSubtree(within, permission.method, path);
        }
        return reached.some((reach) => reaches(reach, permission.method, path));
      },
    );
    if (result.bundle.permissions.length === 0) {
      return refused(`${origins}: no operation of ${value}'s document is reached by its routes`);
    }
    return {
      service: {
        bundle: result.bundle,
        rules: result.rules,
        catalog: emitCatalog(result.bundle),
        derivation: result.derivation,
      },
      problems: [],
    };
  } catch (error) {
    return refused(`${origins}: ${(error as Error).message}`);
  }
}

/**
 * Composes every prefix the routes key. A prefix with a problem keeps what it
 * last composed to, or stays absent if it never did; the rest go ahead. A
 * collision between prefixes refuses the whole reconcile, since no one prefix
 * can be held to fix it.
 */
export function reconcile(
  declared: Declared[],
  names: ResourceNames = {},
  previous?: { services?: Record<string, ComposedService> },
  servesAs?: string,
): Reconciled {
  const origins = declared.map((d) => d.origin);
  const byValue = new Map<string, Declared[]>();
  for (const entry of declared) byValue.set(entry.service, [...(byValue.get(entry.service) ?? []), entry]);

  const problems: Problem[] = [];
  const held: string[] = [];
  const services: Record<string, ComposedService> = {};

  for (const [value, entries] of [...byValue].sort(([a], [b]) => a.localeCompare(b))) {
    const one = composeOne(entries, names, servesAs);
    if (one.service !== undefined) {
      services[value] = one.service;
      continue;
    }
    problems.push(...one.problems);
    held.push(value);
    const kept = previous?.services?.[value];
    if (kept !== undefined) services[value] = kept;
  }

  const composition = compose(Object.values(services), names);
  if (composition.problems.length > 0) {
    return { problems: [...problems, ...composition.problems], held, origins, services };
  }

  return { composition, problems, held, origins, services };
}
