import { JsonPointer } from 'json-ptr';
import { stringify } from 'yaml';

import { CANONICAL_STUBS, emitNamespace } from './emit-model';
import { AccessRule } from './emit-rules';
import { ketoNamespace } from './keto-name';
import { Problem } from './problem';
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
  rules: AccessRule[];
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
  /** Each service's access rules, keyed by service name. */
  rules: Record<string, AccessRule[]>;
  model: string;
  catalog: ServiceCatalog[];
  derivation: string;
  problems: Problem[];
  /** Resource name members whose service is not composed: they bind nothing until it is. */
  unbound: Problem[];
}

/**
 * The gateway loads one rules file. Services keep their own so a reviewer can
 * see whose rule is whose, and this is the order the gateway reads them in.
 */
export const accessRules = (rules: Record<string, AccessRule[]>): string =>
  stringify(
    Object.keys(rules)
      .sort()
      .flatMap((service) => rules[service] ?? []),
    { lineWidth: 0 },
  );

const HTTP_PROTOCOLS: readonly string[] = ['http:', 'https:'];

/** RFC 6901, as the reader of the source resolves it. */
const isPointer = (value: string): boolean => {
  try {
    JsonPointer.decode(value);
    return true;
  } catch {
    return false;
  }
};

/**
 * A source is a claim that one composed operation answers this noun's whole
 * id set. Everything the claim rests on is checkable here, and a claim that
 * does not hold is a sync that would write ids nothing can grant.
 */
export const sourceProblems = (label: string, name: ResourceName): Problem[] => {
  const source = name.source;
  if (source === undefined) return [];

  const messages: string[] = [];
  const url = URL.parse(source.url);
  if (url === null || !HTTP_PROTOCOLS.includes(url.protocol)) {
    messages.push(`resource name ${label}: source.url "${source.url ?? ''}" is not an http(s) URL`);
  }

  for (const [key, value] of [['list', source.list], ['id', source.id], ['label', source.label]] as const) {
    if (value !== undefined && !isPointer(value)) {
      messages.push(`resource name ${label}: source.${key} "${value}" is not a JSON Pointer ("" or /...)`);
    }
  }
  if (source.id === undefined) {
    messages.push(`resource name ${label}: source.id must point at the id within each item`);
  }
  return messages.map((message) => ({ message, resourceNames: [label] }));
};

/** The services each resource name lists, by service, with the type each spells it as. */
export const membersByService = (names: ResourceNames): Map<string, Map<string, string>> => {
  const byService = new Map<string, Map<string, string>>();
  for (const [resourceName, declared] of Object.entries(names.resourceNames ?? {})) {
    for (const member of declared.members) {
      const types = byService.get(member.service) ?? new Map<string, string>();
      types.set(member.type, resourceName);
      byService.set(member.service, types);
    }
  }
  return byService;
};

export function compose(services: ComposedService[], names: ResourceNames = {}): Composition {
  const problems: Problem[] = [];

  const seenService = new Map<string, number>();
  const seenNamespace = new Map<string, string>();
  const seenPermission = new Map<string, string>();
  const seenMatch = new Map<string, Map<string, string>>();

  const known = membersByService(names);

  for (const service of services) {
    const name = service.bundle.service;
    seenService.set(name, (seenService.get(name) ?? 0) + 1);

    const namespace = ketoNamespace(name);
    const holder = seenNamespace.get(namespace);
    if (holder !== undefined && holder !== name) {
      problems.push({ message: `${holder} and ${name} are both Keto namespace ${namespace}`, services: [holder, name] });
    } else seenNamespace.set(namespace, name);

    for (const permission of service.bundle.permissions) {
      const owner = seenPermission.get(permission.id);
      if (owner !== undefined) {
        problems.push({ message: `permission ${permission.id} is claimed by ${owner} and ${name}`, services: [owner, name] });
      } else seenPermission.set(permission.id, name);
    }

    for (const { id } of service.rules) {
      const owner = seenPermission.get(id);
      if (owner !== undefined && owner !== name) problems.push({ message: `rule ${id} collides with ${owner}`, services: [owner, name] });
    }

    // Oathkeeper answers 500 when two rules match one request, so a match
    // claimed twice is a rollout that must not happen. Identical matches are
    // what registering two services on one host produces; a partial overlap
    // needs the live gateway to find and is caught by the conformance probe.
    for (const { match } of service.rules) {
      const methods = seenMatch.get(match.url) ?? new Map<string, string>();
      for (const method of match.methods) {
        const owner = methods.get(method);
        if (owner !== undefined) {
          problems.push({ message: `${name} and ${owner} both match ${method} ${match.url}`, services: [name, owner] });
        } else methods.set(method, name);
      }
      seenMatch.set(match.url, methods);
    }

    // The vocabulary is total: every type a service is about is picked and
    // labelled by the noun that names it, so a type outside it is a grantable
    // thing the deployment never blessed.
    for (const type of service.bundle.resourceTypes) {
      if (known.get(name)?.has(type) !== true) {
        problems.push({ message: `${name} is about ${type}, and no resource name lists ${name}.${type}`, services: [name] });
      }
    }
  }

  for (const [name, count] of seenService) {
    if (count > 1) problems.push({ message: `service ${name} is registered ${count} times`, services: [name] });
  }

  // A resource name is an assertion about two services' vocabularies, and an
  // assertion nobody checks is a grant an operator writes that never binds
  // anything. Every member has to be a type its service is really about.
  const declaredBy = new Map(services.map((s) => [s.bundle.service, new Set(s.bundle.resourceTypes)]));
  const unbound: Problem[] = [];
  for (const [label, name] of Object.entries(names.resourceNames ?? {})) {
    for (const member of name.members) {
      const types = declaredBy.get(member.service);
      if (types === undefined) {
        unbound.push({
          message: `resource name ${label} lists ${member.service}, which this deployment does not compose`,
          resourceNames: [label],
        });
      } else if (!types.has(member.type)) {
        problems.push({
          message: `resource name ${label} lists ${member.service}.${member.type}, which ${member.service} is not about`,
          resourceNames: [label],
          services: [member.service],
        });
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
