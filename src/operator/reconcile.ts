import { clientPath, emitCatalog, generate, reachesSubtree, Rewrite } from '../authzgen';
import {
  compose,
  ComposedService,
  Composition,
  diffCatalogs,
  Migrations,
  ResourceNames,
  ungated,
} from '../authzgen/compose';
import { ServiceCatalog } from '../authzgen/types';
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

/** One keyed backend, as one route sends traffic to it. */
export interface Declared {
  /** Where it came from, for a message an operator can act on. */
  origin: string;
  /** The permission prefix the route gives the backend. */
  service: string;
  /** `<namespace>/<name>` of the Service: the prefix's one source. */
  backend: string;
  /** Where its document is read: the backend's own URL, or the AuthzDocument the route names. */
  source: string;
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
  problems: string[];
  /** Prefixes kept at their last composed state because something about them is wrong. */
  held: string[];
  /** Which origins were read. */
  origins: string[];
  /** What each composed prefix was built from, for the next pass to hold. */
  services: Record<string, ComposedService>;
}

const rewriteKey = (rewrite?: Rewrite): string => (rewrite === undefined ? '' : `${rewrite.from}→${rewrite.to}`);

/** Composes one prefix, or says why it cannot. */
function composeOne(entries: Declared[], names: ResourceNames): { service?: ComposedService; problems: string[] } {
  const value = entries[0]!.service;
  const sources = [...new Set(entries.map((e) => e.backend))].sort();
  if (sources.length > 1) {
    return {
      problems: [
        `${value} is keyed on ${sources.join(' and ')}; a prefix belongs to one Service (${entries.map((e) => e.origin).join(', ')})`,
      ],
    };
  }

  const documents = [...new Set(entries.map((e) => e.source))].sort();
  if (documents.length > 1) {
    return { problems: [`${value} is read from ${documents.join(' and ')}; a prefix has one document`] };
  }

  const byHosts = new Map<string, Set<string>>();
  for (const entry of entries) {
    const hosts = [...entry.hosts].sort().join(',');
    const mounts = byHosts.get(hosts) ?? new Set<string>();
    for (const reach of entry.reaches) for (const match of reach.matches) mounts.add(JSON.stringify(match));
    byHosts.set(hosts, mounts);
  }
  const shapes = new Set([...byHosts.values()].map((mounts) => [...mounts].sort().join('|')));
  if (shapes.size > 1) {
    return {
      problems: [`${value} is reached through different paths on ${[...byHosts.keys()].sort().join(' and ')}`],
    };
  }

  const unread = entries.filter((e) => e.problem !== undefined || e.document === undefined);
  if (unread.length > 0) {
    return { problems: unread.map((e) => `${e.origin}: ${e.problem ?? 'no document'}`) };
  }

  const reached = entries.flatMap((e) => e.reaches);
  const rewrites = [...new Set(reached.map((r) => rewriteKey(r.rewrite)))];
  if (rewrites.length > 1) {
    return {
      problems: [`${value} is reached through different rewrites (${rewrites.map((r) => r || 'none').join(', ')})`],
    };
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
      { hosts, ...(rewrite !== undefined ? { rewrite } : {}), exclude, within },
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
      return {
        problems: [`${entries.map((e) => e.origin).join(', ')}: no operation of ${value}'s document is reached by its routes`],
      };
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
    return { problems: [`${entries.map((e) => e.origin).join(', ')}: ${(error as Error).message}`] };
  }
}

/**
 * Composes every prefix the routes key. A prefix with a problem keeps what it
 * last composed to, or stays absent if it never did; the rest go ahead. A
 * collision between prefixes, or a change that would strand grants, refuses
 * the whole reconcile, since no one prefix can be held to fix it.
 */
export function reconcile(
  declared: Declared[],
  names: ResourceNames = {},
  previous?: { catalog?: ServiceCatalog[]; services?: Record<string, ComposedService> },
  migrations: Migrations = {},
): Reconciled {
  const origins = declared.map((d) => d.origin);
  const byValue = new Map<string, Declared[]>();
  for (const entry of declared) byValue.set(entry.service, [...(byValue.get(entry.service) ?? []), entry]);

  const problems: string[] = [];
  const held: string[] = [];
  const services: Record<string, ComposedService> = {};

  for (const [value, entries] of [...byValue].sort(([a], [b]) => a.localeCompare(b))) {
    const one = composeOne(entries, names);
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

  // A permission that changed shape or left is a grant that silently means
  // something else, or nothing. The deployment says what happens to those
  // before the change reaches the gateway.
  if (previous?.catalog !== undefined) {
    const unresolved = ungated(diffCatalogs(previous.catalog, composition.catalog), migrations);
    if (unresolved.length > 0) return { problems: [...problems, ...unresolved], held, origins, services };
  }

  return { composition, problems, held, origins, services };
}
