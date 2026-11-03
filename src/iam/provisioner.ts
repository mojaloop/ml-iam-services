import { ResourceNames } from '../authzgen/compose';
import { ALL, idProblem } from '../authzgen/reserved';
import { Logged } from '../logged';
import { broken, holdingsOf } from './exclusions';
import { difference, KetoReads, KetoWriter } from './keto';
import { materializeRole, MEMBERS, membership, parseInstance, ROLE_NAMESPACE, roleObject, Tuple } from './materialize';
import { provision, ProvisionRequest } from './provision';
import { EXISTS, parseResource, RESOURCE_NAMESPACE, ResourceInstance } from './registry';
import { openResourceNames, PermissionIndex, RoleDocument, RolesFile } from './roles';
import { Listed, ResourceSources } from './sources';

export interface Assignment {
  role: string;
  resources: Record<string, string>;
}

/** What retiring resources did: who held a role over them, and who of those holds no role anywhere now. */
export interface Deprovisioned {
  orphaned: string[];
  members: string[];
  problem?: string;
}

/** What a resource name lists for its object's status: how many, as of when its source was read, and why a read failed. */
export interface ResourceCount {
  resources: number;
  read?: string;
  failed?: string;
  misdeclared?: true;
}

/** Every subject a member of some instance of the role. */
export async function subjectsHolding(keto: KetoReads, role: string): Promise<string[]> {
  const held = await keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS });
  return [
    ...new Set(
      held.filter((t) => parseInstance(t.object).role === role && t.subject_id !== undefined).map((t) => t.subject_id!),
    ),
  ];
}

/** What a subject holds: one entry per role instance they are a member of. */
export async function assignmentsOf(keto: KetoReads, subject: string): Promise<Assignment[]> {
  const held = await keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS, subject_id: subject });
  return held.map((t) => parseInstance(t.object));
}

/**
 * Writes what a provisioning request means, and unwinds it again. The only
 * component that holds Keto write access, so a service can cause permissions
 * to exist without ever holding the pen.
 */
export class Provisioner {
  private readonly sources: ResourceSources;
  /** Told the figures of every resource name this process lists, as each one's object shows them. */
  onListed?: (figures: Record<string, ResourceCount>) => void;
  /** Roles waiting for a service, which their members hold again once it is composed. */
  private waiting: Record<string, RoleDocument> = {};

  constructor(
    private readonly keto: KetoWriter,
    private roles: RolesFile,
    private index: PermissionIndex,
    private names: ResourceNames = {},
    fetchImpl: typeof fetch = fetch,
  ) {
    this.sources = new ResourceSources(() => this.names, fetchImpl);
  }

  /** The roles and catalog that are live now, as compositions add services. */
  use(roles: RolesFile, index: PermissionIndex, waiting: Record<string, RoleDocument> = {}): void {
    this.roles = roles;
    this.index = index;
    this.waiting = waiting;
  }

  /** The deployment's vocabulary as its resource names now declare it. */
  useNames(names: ResourceNames): void {
    this.names = names;
  }

  /** The declared vocabulary is the registry's key space, so a name outside it is refused. */
  private declared(resourceName: string): { problem?: string } {
    if (this.names.resourceNames?.[resourceName] === undefined) {
      return { problem: `no resource name called ${resourceName}` };
    }
    return {};
  }

  async provision(request: ProvisionRequest): Promise<{ problem?: string }> {
    const problem = this.declared(request.resourceName).problem ?? idProblem(request.id);
    if (problem !== undefined) return { problem };
    for (const tuple of provision(request.resourceName, request.id)) await this.keto.put(tuple);
    this.relist(request.resourceName);
    return {};
  }

  /** Records many resources of one name the registry does not hold yet, in one write. */
  async provisionAll(resourceName: string, ids: string[]): Promise<{ problem?: string }> {
    const problem = this.declared(resourceName).problem ?? ids.map(idProblem).find((p) => p !== undefined);
    if (problem !== undefined) return { problem };
    if (ids.length === 0) return {};
    await this.keto.patch(ids.flatMap((id) => provision(resourceName, id)), []);
    this.relist(resourceName);
    return {};
  }

  /**
   * Retires every role instance that stands for the resource, and answers
   * with the subjects that held one, and those of them that now hold no role
   * anywhere. A caller that owns identities can retire those without ever
   * reading the graph.
   */
  async deprovision(request: ProvisionRequest): Promise<Deprovisioned> {
    return this.deprovisionAll(request.resourceName, [request.id]);
  }

  /** Retires resources of one name together, in as many reads and writes as one takes. */
  async deprovisionAll(resourceName: string, ids: string[]): Promise<Deprovisioned> {
    const { problem } = this.declared(resourceName);
    if (problem !== undefined) return { orphaned: [], members: [], problem };
    if (ids.length === 0) return { orphaned: [], members: [] };
    const gone = new Set(ids);

    const [held, modelled, registered] = await Promise.all([
      this.keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS }),
      this.keto.namespaces(),
      this.keto.query({ namespace: RESOURCE_NAMESPACE, relation: EXISTS }),
    ]);
    const recorded = registered.filter((tuple) => {
      const resource = parseResource(tuple.object);
      return resource?.resourceName === resourceName && gone.has(resource.id);
    });
    const over = (tuple: Tuple) => {
      const id = parseInstance(tuple.object).resources[resourceName];
      return id !== undefined && gone.has(id);
    };
    const retiring = held.filter(over);
    const objects = [...new Set(retiring.map((tuple) => tuple.object))];
    const grants = await Promise.all(objects.map((object) => this.keto.grantsOf(object, new Set(modelled))));
    await this.keto.patch([], difference([], [...grants.flat(), ...retiring, ...recorded]).deletes);

    const members = new Set(retiring.flatMap((tuple) => (tuple.subject_id !== undefined ? [tuple.subject_id] : [])));
    const remaining = new Set(held.filter((tuple) => !over(tuple)).map((tuple) => tuple.subject_id));
    this.relist(resourceName);
    return { orphaned: [...members].filter((subject) => !remaining.has(subject)), members: [...members] };
  }

  /**
   * The resources an operator can be offered, optionally of one resource
   * name: the ones services recorded, and what each declared source lists
   * now, read for this question. A source that did not answer is named with
   * its reason, and its last good read stands in for it.
   */
  async listed(resourceName?: string): Promise<{
    resources: ResourceInstance[];
    stale: Record<string, NonNullable<Listed['stale']>>;
    read: Record<string, string>;
  }> {
    const sourced = resourceName === undefined ? this.sources.declared() : [resourceName];
    const [rows, reads] = await Promise.all([
      this.keto.query({ namespace: RESOURCE_NAMESPACE, relation: EXISTS }),
      Promise.all(sourced.map(async (name) => [name, await this.sources.ids(name)] as const)),
    ]);
    const found = new Map<string, Set<string>>();
    const add = ({ resourceName: name, id }: ResourceInstance): void => {
      found.set(name, (found.get(name) ?? new Set<string>()).add(id));
    };
    for (const r of rows.map((t) => parseResource(t.object))) {
      if (r !== undefined && (resourceName === undefined || r.resourceName === resourceName)) add(r);
    }
    const stale: Record<string, NonNullable<Listed['stale']>> = {};
    const read: Record<string, string> = {};
    for (const [name, listing] of reads) {
      if (listing === undefined) continue;
      if (listing.stale !== undefined) stale[name] = listing.stale;
      if (listing.read !== undefined) read[name] = listing.read;
      for (const id of listing.ids) add({ resourceName: name, id });
    }
    const resources = [...found]
      .sort(([a], [b]) => a.localeCompare(b))
      .flatMap(([name, ids]) => [...ids].sort().map((id) => ({ resourceName: name, id })));
    const covered = resourceName === undefined ? Object.keys(this.names.resourceNames ?? {}) : [resourceName];
    this.onListed?.(
      Object.fromEntries(
        covered.map((name): [string, ResourceCount] => [
          name,
          {
            resources: resources.filter((r) => r.resourceName === name).length,
            ...(read[name] !== undefined ? { read: read[name] } : {}),
            ...(stale[name] !== undefined ? { failed: stale[name].reason } : {}),
            ...(stale[name]?.misdeclared === true ? { misdeclared: true as const } : {}),
          },
        ]),
      ),
    );
    return { resources, stale, read };
  }

  /** A resource name's figures, read now, as its object shows them. */
  async count(resourceName: string): Promise<ResourceCount> {
    const { resources, stale, read } = await this.listed(resourceName);
    return {
      resources: resources.length,
      ...(read[resourceName] !== undefined ? { read: read[resourceName] } : {}),
      ...(stale[resourceName] !== undefined ? { failed: stale[resourceName].reason } : {}),
      ...(stale[resourceName]?.misdeclared === true ? { misdeclared: true as const } : {}),
    };
  }

  /** Lists a resource name again after its recorded resources changed, so whoever follows the figures hears of it. */
  private relist(resourceName: string): void {
    if (this.onListed === undefined) return;
    this.listed(resourceName).catch((error) =>
      console.error(JSON.stringify({ event: Logged.relistFailed, resourceName, error: String(error) })),
    );
  }

  async resources(resourceName?: string): Promise<ResourceInstance[]> {
    return (await this.listed(resourceName)).resources;
  }

  async assignments(subject: string): Promise<Assignment[]> {
    return assignmentsOf(this.keto, subject);
  }

  /**
   * Every way an assignment can be wrong, before anything is written: the
   * role has to exist, and the resources named have to be keyed by exactly
   * the resource names its grants leave open.
   *
   * Whether each named resource exists is asked only when granting. Taking a
   * membership away stays possible after the resource is gone, since refusing
   * would strand exactly the grants worth removing. `$all` is every resource
   * of its name, present or not; whether the assigner may name it is their
   * scope's to say.
   */
  async problemsWith(subject: string, assignment: Assignment, granting = true): Promise<string[]> {
    const role = this.roles.roles[assignment.role];
    if (role === undefined) return [`unknown role ${assignment.role}`];
    if (role.heldBy !== undefined) {
      return [`role ${assignment.role} is held by every ${role.heldBy} subject and is never assigned`];
    }

    const expected = openResourceNames(role, this.index);
    const given = Object.keys(assignment.resources);
    const missing = expected.filter((n) => !given.includes(n));
    const extra = given.filter((n) => !expected.includes(n));
    if (missing.length > 0 || extra.length > 0) {
      return [`role ${assignment.role} takes [${expected.join(',')}], got [${given.join(',')}]`];
    }
    if (!granting) return [];

    const problems: string[] = [];
    for (const [resourceName, id] of Object.entries(assignment.resources)) {
      if (id === ALL) continue;
      const { resources, stale } = await this.listed(resourceName);
      if (resources.some((r) => r.id === id)) continue;
      const unread = stale[resourceName];
      problems.push(
        unread === undefined
          ? `no ${resourceName} called ${id}`
          : `no ${resourceName} called ${id} as of ${unread.since ?? 'no read'}: its source did not answer (${unread.reason})`,
      );
    }
    return [...problems, ...(await this.separationProblems(subject, assignment))];
  }

  /**
   * Separation of duties, asked of the holding this assignment would produce:
   * the rule is that no one pair of hands ends up with both sides, and it
   * takes two roles to get there.
   */
  async separationProblems(subject: string, assignment: Assignment): Promise<string[]> {
    const exclusions = this.roles.exclusions ?? [];
    if (exclusions.length === 0) return [];

    const held = await this.assignments(subject);
    const roles = { roles: { ...this.waiting, ...this.roles.roles } };
    return broken(holdingsOf(roles, [...held, assignment]), exclusions, this.index);
  }

  /**
   * Adds a subject to a role instance, materializing that instance's grants
   * first, since a role with open resource names holds nothing until an
   * assignment names what it is about.
   */
  async assign(subject: string, assignment: Assignment): Promise<{ instance: string }> {
    const role = this.roles.roles[assignment.role]!;
    const object = roleObject(assignment.role, assignment.resources);
    const modelled = new Set(await this.keto.namespaces());
    const [held, holding] = await Promise.all([
      this.keto.grantsOf(object, modelled),
      this.keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS, subject_id: subject }),
    ]);
    const { inserts, deletes } = difference(materializeRole(assignment.role, role, this.index, assignment.resources), held);
    const absent = difference([membership(assignment.role, subject, assignment.resources)], holding).inserts;
    await this.keto.patch([...inserts, ...absent], deletes);
    return { instance: object };
  }

  /**
   * Removes one subject's membership of an instance, and leaves the instance
   * standing, because another subject may hold it. An instance nobody holds
   * grants nobody anything.
   */
  async unassign(subject: string, assignment: Assignment): Promise<{ instance: string }> {
    const object = roleObject(assignment.role, assignment.resources);
    await this.keto.deleteWhere({ namespace: ROLE_NAMESPACE, object, relation: MEMBERS, subject_id: subject });
    return { instance: object };
  }
}
