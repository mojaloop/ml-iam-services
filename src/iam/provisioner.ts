import { ResourceNames } from '../authzgen/compose';
import { broken, holdingsOf } from './exclusions';
import { difference, filterFor, KetoWriter } from './keto';
import { materializeRole, MEMBERS, membership, parseInstance, ROLE_NAMESPACE, roleObject, Tuple } from './materialize';
import { provision, ProvisionRequest } from './provision';
import {
  EXISTS,
  parseResource,
  registryTuple,
  RESOURCE_NAMESPACE,
  ResourceInstance,
} from './registry';
import { openResourceNames, PermissionIndex, RolesFile } from './roles';

export interface Assignment {
  role: string;
  resources: Record<string, string>;
}

/**
 * Writes what a provisioning request means, and unwinds it again. The only
 * component that holds Keto write access, so a service can cause permissions
 * to exist without ever holding the pen.
 */
export class Provisioner {
  constructor(
    private readonly keto: KetoWriter,
    private roles: RolesFile,
    private index: PermissionIndex,
    private names: ResourceNames = {},
  ) {}

  /** The roles and catalog that are live now, as compositions add services. */
  use(roles: RolesFile, index: PermissionIndex): void {
    this.roles = roles;
    this.index = index;
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
    const { problem } = this.declared(request.resourceName);
    if (problem !== undefined) return { problem };
    for (const tuple of provision(request.resourceName, request.id)) await this.keto.put(tuple);
    return {};
  }

  /** The role instances that stand for this resource, read from what holds them. */
  private async instancesOf(resourceName: string, id: string): Promise<string[]> {
    const held = await this.keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS });
    const objects = new Set<string>();
    for (const tuple of held) {
      if (parseInstance(tuple.object).resources[resourceName] === id) objects.add(tuple.object);
    }
    return [...objects];
  }

  /**
   * Retires every role instance that stands for the resource, and answers
   * with the subjects that now hold no role anywhere. A caller that owns
   * identities can retire those without ever reading the graph.
   */
  async deprovision(request: ProvisionRequest): Promise<{ orphaned: string[]; problem?: string }> {
    const { problem } = this.declared(request.resourceName);
    if (problem !== undefined) return { orphaned: [], problem };
    const { resourceName } = request;

    const instances = await this.instancesOf(resourceName, request.id);
    const modelled = new Set(await this.keto.namespaces());

    const retired: Tuple[] = [];
    const members = new Set<string>();
    for (const instance of instances) {
      const memberships = await this.keto.query({ namespace: ROLE_NAMESPACE, object: instance, relation: MEMBERS });
      for (const tuple of memberships) if (tuple.subject_id !== undefined) members.add(tuple.subject_id);
      retired.push(...(await this.keto.grantsOf(instance, modelled)), ...memberships);
    }
    retired.push(
      ...(await this.keto.query({
        namespace: RESOURCE_NAMESPACE,
        object: registryTuple(resourceName, request.id).object,
        relation: EXISTS,
      })),
    );
    await this.keto.patch([], difference([], retired).deletes);

    const orphaned: string[] = [];
    for (const subject of members) {
      const remaining = await this.keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS, subject_id: subject });
      if (remaining.length === 0) orphaned.push(subject);
    }
    return { orphaned };
  }

  /** The resources an operator can be offered, optionally of one resource name. */
  async resources(resourceName?: string): Promise<ResourceInstance[]> {
    const rows = await this.keto.query({ namespace: RESOURCE_NAMESPACE, relation: EXISTS });
    return rows
      .map((t) => parseResource(t.object))
      .filter(
        (r): r is ResourceInstance =>
          r !== undefined && (resourceName === undefined || r.resourceName === resourceName),
      )
      .sort((a, b) => `${a.resourceName}/${a.id}`.localeCompare(`${b.resourceName}/${b.id}`));
  }

  /** What a subject holds: one entry per role instance they are a member of. */
  async assignments(subject: string): Promise<Assignment[]> {
    const held = await this.keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS, subject_id: subject });
    return held.map((t) => parseInstance(t.object));
  }

  /**
   * Every way an assignment can be wrong, before anything is written: the
   * role has to exist, and the resources named have to be keyed by exactly
   * the resource names its grants leave open.
   *
   * Whether each named resource exists is asked only when granting. Taking a
   * membership away stays possible after the resource is gone, since refusing
   * would strand exactly the grants worth removing.
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
      const known = await this.resources(resourceName);
      if (!known.some((r) => r.id === id)) problems.push(`no ${resourceName} called ${id}`);
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
    return broken(holdingsOf(this.roles, [...held, assignment]), exclusions, this.index);
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
    const { inserts, deletes } = difference(
      materializeRole(assignment.role, role, this.index, assignment.resources),
      await this.keto.grantsOf(object, modelled),
    );
    const member = membership(assignment.role, subject, assignment.resources);
    const absent = (await this.keto.query(filterFor(member))).length === 0;
    await this.keto.patch([...inserts, ...(absent ? [member] : [])], deletes);
    return { instance: object };
  }

  /**
   * Removes one membership and leaves the instance standing, because another
   * subject may hold it. An instance nobody holds grants nobody anything.
   */
  async unassign(subject: string, assignment: Assignment): Promise<{ instance: string }> {
    const object = roleObject(assignment.role, assignment.resources);
    await this.keto.deleteWhere({
      namespace: ROLE_NAMESPACE,
      object,
      relation: MEMBERS,
      subject_id: subject,
    });
    return { instance: object };
  }
}
