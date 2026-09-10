import { ResourceNames } from '../authzgen/compose';
import { broken, permissionsOf, rolesNamed } from './exclusions';
import { KetoWriter } from './keto';
import { materializeRole, MEMBERS, membership, ROLE_NAMESPACE,roleObject } from './materialize';
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

/** A role instance object read back into the role and the resources it stands for. */
export const parseInstance = (object: string): Assignment => {
  const at = object.indexOf('@');
  if (at < 0) return { role: object, resources: {} };
  const resources: Record<string, string> = {};
  for (const pair of object.slice(at + 1).split(',')) {
    const eq = pair.indexOf('=');
    if (eq > 0) resources[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
  return { role: object.slice(0, at), resources };
};

/**
 * Writes what a provisioning request means, and unwinds it again. The only
 * component that holds Keto write access, so a service can cause permissions
 * to exist without ever holding the pen.
 */
export class Provisioner {
  constructor(
    private readonly keto: KetoWriter,
    private readonly roles: RolesFile,
    private readonly index: PermissionIndex,
    private readonly names: ResourceNames = {},
  ) {}

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
    await this.keto.putAll(provision(request.resourceName, request.id));
    return {};
  }

  /** Members of a role instance, as subject ids. */
  private async membersOf(object: string): Promise<string[]> {
    const tuples = await this.keto.query({ namespace: ROLE_NAMESPACE, object, relation: MEMBERS });
    return tuples.map((t) => t.subject_id).filter((id): id is string => id !== undefined);
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

    const members = new Set<string>();
    for (const instance of instances) {
      for (const subject of await this.membersOf(instance)) members.add(subject);
    }

    for (const instance of instances) {
      // The grants point at the instance's member set, so that subject set
      // finds them all.
      await this.keto.clearGrantsOf(instance);
      await this.keto.deleteWhere({ namespace: ROLE_NAMESPACE, object: instance, relation: MEMBERS });
    }

    await this.keto.deleteWhere({
      namespace: RESOURCE_NAMESPACE,
      object: registryTuple(resourceName, request.id).object,
      relation: EXISTS,
    });

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

    const held = (await this.assignments(subject)).map((a) => a.role);
    const after = rolesNamed(this.roles, [...held, assignment.role]);
    return broken(permissionsOf(after), exclusions);
  }

  /**
   * Adds a subject to a role instance, materializing that instance's grants
   * first, since a role with open resource names holds nothing until an
   * assignment names what it is about.
   */
  async assign(subject: string, assignment: Assignment): Promise<{ instance: string }> {
    const role = this.roles.roles[assignment.role]!;
    const object = roleObject(assignment.role, assignment.resources);
    await this.keto.clearGrantsOf(object);
    await this.keto.putAll(materializeRole(assignment.role, role, this.index, assignment.resources));
    await this.keto.put(membership(assignment.role, subject, assignment.resources));
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
