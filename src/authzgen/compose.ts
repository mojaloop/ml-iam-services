import { CANONICAL_STUBS, emitNamespace } from './emit-model';
import { ketoNamespace } from './keto-name';
import { ServiceBundle, ServiceCatalog } from './types';

/**
 * Composition: every registered service's derived surface, checked against
 * every other's and staged as the files Oathkeeper and Keto boot from.
 *
 * A service is derived alone and is correct alone. What only shows up with the
 * deployment in one place is collision — two services claiming one permission
 * id, two rules claiming one request, a resource type nobody in the deployment
 * can name — so that is what this decides, once per rollout, before anything
 * is written.
 */

export interface ComposedService {
  bundle: ServiceBundle;
  rules: string;
  catalog: ServiceCatalog;
  derivation: string;
}

/**
 * Who is authoritative for this resource name's ids, for a deployment whose
 * list lives in a system that never provisions them. The listing must answer
 * the whole set; the pointers are RFC 6901.
 */
export interface ResourceSource {
  /** The listing, read in-cluster. Each id it answers registers under the resource name. */
  url: string;
  /** To the array in the response body; omitted, the body is the array. */
  list?: string;
  /** To the id within each item: what grants bind and the registry records. */
  id: string;
  /** To a display text within each item, for consumers that render the rows. */
  label?: string;
}

/** Display text: one string, or one per language for a UI to pick from. */
export type Localized = string | Record<string, string>;

/**
 * The deployment's canonical name for one real thing carrying different
 * spellings in different documents. Inside the deployment the resource name
 * keys the resource (`Customer/acme`), and each document's spelling is a
 * member. A type no path binds is legitimate — a reporting service returns
 * customer rows while routing no `/customers` — so it is checked against
 * this.
 *
 * Served verbatim once composed: every consumer reads the same declaration
 * and takes the fields it needs.
 */
export interface ResourceName {
  label?: Localized;
  description?: Localized;
  members: Array<{ service: string; type: string }>;
  source?: ResourceSource;
}

export interface ResourceNames {
  resourceNames?: Record<string, ResourceName>;
}

export interface Composition {
  /** One rules file per service, keyed by service name. */
  rules: Record<string, string>;
  model: string;
  catalog: ServiceCatalog[];
  derivation: string;
  problems: string[];
  /** Resource name members whose service is not composed: they bind nothing until it is. */
  unbound: string[];
}

const ruleIds = (rules: string): string[] =>
  rules
    .split('\n')
    .filter((line) => line.startsWith('- id: '))
    .map((line) => line.slice('- id: '.length).trim());

const matchKeys = (rules: string): string[] => {
  const keys: string[] = [];
  let url: string | undefined;
  for (const line of rules.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('url: ')) url = trimmed.slice('url: '.length);
    else if (trimmed.startsWith('- ') && url !== undefined && /^- [A-Z]+$/.test(trimmed)) {
      keys.push(`${trimmed.slice(2)} ${url}`);
    }
  }
  return keys;
};

/**
 * The gateway loads one rules file. Services keep their own so a reviewer can
 * see whose rule is whose, and this is the order the gateway reads them in.
 */
export const accessRules = (rules: Record<string, string>): string =>
  Object.keys(rules)
    .sort()
    .map((service) => {
      const text = rules[service] ?? '';
      return text.endsWith('\n') ? text : `${text}\n`;
    })
    .join('');

/** RFC 6901: the whole document, or a token path from its root. */
const isPointer = (value: string): boolean => value === '' || value.startsWith('/');

/**
 * A source is a claim that one composed operation answers this noun's whole
 * id set. Everything the claim rests on is checkable here, and a claim that
 * does not hold is a sync that would write ids nothing can grant.
 */
const sourceProblems = (label: string, name: ResourceName): string[] => {
  const source = name.source;
  if (source === undefined) return [];

  const problems: string[] = [];
  try {
    const url = new URL(source.url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error();
  } catch {
    problems.push(`resource name ${label}: source.url "${source.url ?? ''}" is not an http(s) URL`);
  }

  for (const [key, value] of [['list', source.list], ['id', source.id], ['label', source.label]] as const) {
    if (value !== undefined && !isPointer(value)) {
      problems.push(`resource name ${label}: source.${key} "${value}" is not a JSON Pointer ("" or /...)`);
    }
  }
  if (source.id === undefined) {
    problems.push(`resource name ${label}: source.id must point at the id within each item`);
  }
  return problems;
};

export function compose(services: ComposedService[], names: ResourceNames = {}): Composition {
  const problems: string[] = [];

  const seenService = new Map<string, number>();
  const seenNamespace = new Map<string, string>();
  const seenPermission = new Map<string, string>();
  const seenMatch = new Map<string, string>();

  const known = new Set(
    Object.values(names.resourceNames ?? {}).flatMap((n) => n.members.map((m) => `${m.service}.${m.type}`)),
  );

  for (const service of services) {
    const name = service.bundle.service;
    seenService.set(name, (seenService.get(name) ?? 0) + 1);

    const namespace = ketoNamespace(name);
    const holder = seenNamespace.get(namespace);
    if (holder !== undefined && holder !== name) {
      problems.push(`${holder} and ${name} are both Keto namespace ${namespace}`);
    } else seenNamespace.set(namespace, name);

    for (const permission of service.bundle.permissions) {
      const owner = seenPermission.get(permission.id);
      if (owner !== undefined) problems.push(`permission ${permission.id} is claimed by ${owner} and ${name}`);
      else seenPermission.set(permission.id, name);
    }

    for (const id of ruleIds(service.rules)) {
      const owner = seenPermission.get(id);
      if (owner !== undefined && owner !== name) problems.push(`rule ${id} collides with ${owner}`);
    }

    // Oathkeeper answers 500 when two rules match one request, so a match
    // claimed twice is a rollout that must not happen. Identical matches are
    // what registering two services on one host produces; a partial overlap
    // needs the live gateway to find and is caught by the conformance probe.
    for (const key of matchKeys(service.rules)) {
      const owner = seenMatch.get(key);
      if (owner !== undefined) problems.push(`${name} and ${owner} both match ${key}`);
      else seenMatch.set(key, name);
    }

    // The vocabulary is total: every type a service is about is picked and
    // labelled by the noun that names it, so a type outside it is a grantable
    // thing the deployment never blessed.
    for (const type of service.bundle.resourceTypes) {
      if (!known.has(`${name}.${type}`)) {
        problems.push(`${name} is about ${type}, and no resource name lists ${name}.${type}`);
      }
    }
  }

  for (const [name, count] of seenService) {
    if (count > 1) problems.push(`service ${name} is registered ${count} times`);
  }

  // A resource name is an assertion about two services' vocabularies, and an
  // assertion nobody checks is a grant an operator writes that never binds
  // anything. Every member has to be a type its service is really about.
  const declaredBy = new Map(services.map((s) => [s.bundle.service, new Set(s.bundle.resourceTypes)]));
  const unbound: string[] = [];
  for (const [label, name] of Object.entries(names.resourceNames ?? {})) {
    for (const member of name.members) {
      const types = declaredBy.get(member.service);
      if (types === undefined) {
        unbound.push(`resource name ${label} lists ${member.service}, which this deployment does not compose`);
      } else if (!types.has(member.type)) {
        problems.push(`resource name ${label} lists ${member.service}.${member.type}, which ${member.service} is not about`);
      }
    }
    problems.push(...sourceProblems(label, name));
  }

  const ordered = [...services].sort((a, b) => a.bundle.service.localeCompare(b.bundle.service));

  return {
    rules: Object.fromEntries(ordered.map((s) => [s.bundle.service, s.rules])),
    // Keto reads one concatenated file and keeps the last declaration of a
    // duplicated name, so the shared classes are written exactly once.
    model: [CANONICAL_STUBS, ...ordered.map((s) => emitNamespace(s.bundle))].join('\n'),
    catalog: ordered.map((s) => s.catalog),
    derivation: ordered.map((s) => s.derivation).join('\n'),
    problems,
    unbound,
  };
}

/* ------------------------------------------------------------------ *
 * The diff gate                                                       *
 * ------------------------------------------------------------------ */

export interface PermissionChange {
  id: string;
  was: string;
  now: string;
}

export interface CatalogDiff {
  added: string[];
  /** Gone from the catalog: any grant a deployment holds on it is orphaned. */
  removed: string[];
  /** Still present, but a stored tuple written for it no longer answers. */
  changed: PermissionChange[];
}

const shape = (id: string, catalogs: ServiceCatalog[]): string | undefined => {
  for (const catalog of catalogs) {
    const permission = catalog.permissions.find((p) => p.id === id);
    if (permission) return `${permission.relation} over [${[...permission.bound].sort().join(',')}]`;
  }
  return undefined;
};

const idsOf = (catalogs: ServiceCatalog[]): string[] =>
  catalogs.flatMap((c) => c.permissions.map((p) => p.id)).sort();

/**
 * What this rollout does to the permissions a deployment has already granted.
 * An addition is held by nobody until someone grants it, so it is free; a
 * removal or a changed shape leaves stored tuples that answer no check, which
 * takes access away silently.
 */
export function diffCatalogs(previous: ServiceCatalog[], next: ServiceCatalog[]): CatalogDiff {
  const before = idsOf(previous);
  const after = new Set(idsOf(next));

  return {
    added: idsOf(next).filter((id) => !before.includes(id)),
    removed: before.filter((id) => !after.has(id)),
    changed: before
      .filter((id) => after.has(id))
      .map((id) => ({ id, was: shape(id, previous)!, now: shape(id, next)! }))
      .filter((change) => change.was !== change.now),
  };
}

/** Where a permission's grants move to, when a rollout renames or retires one. */
export type Migrations = Record<string, string | null>;

/**
 * A removal or a change is allowed to reach a deployment only when the rollout
 * says what happens to the grants: a new permission id to move them to, or
 * null to retire them.
 */
export function ungated(diff: CatalogDiff, migrations: Migrations = {}): string[] {
  const problems: string[] = [];
  for (const id of diff.removed) {
    if (!(id in migrations)) problems.push(`${id} is gone and no migration says where its grants go`);
  }
  for (const change of diff.changed) {
    if (!(change.id in migrations)) {
      problems.push(`${change.id} was ${change.was} and is now ${change.now}, with no migration`);
    }
  }
  return problems;
}
