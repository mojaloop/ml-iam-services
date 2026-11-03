import { ketoNamespace } from '../authzgen/keto-name';
import { serviceOf } from '../authzgen/permission';
import { ALL, AUTHENTICATED, SINGLETON } from '../authzgen/reserved';
import { resourceObject } from './registry';
import { grantResources, openResourceNames, PermissionIndex, ResourceSet, RoleDocument, RolesFile } from './roles';

/**
 * Role documents in, Keto tuples out. Pure, because this is the one place the
 * model's shape is decided and it has to be checkable without a Keto.
 */

export const ROLE_NAMESPACE = 'Role';
export const MEMBERS = 'members';
export { AUTHENTICATED, SINGLETON } from '../authzgen/reserved';
/** The object a grant over every resource of a name is written to. */
export const TYPE_WIDE = ALL;
/** `Role:<role>#heldBy@$authenticated` marks a role every authenticated subject holds. */
export const HELD_BY = 'heldBy';

export const heldByMarker = (role: string): Tuple => ({
  namespace: ROLE_NAMESPACE,
  object: role,
  relation: HELD_BY,
  subject_id: AUTHENTICATED,
});

export interface SubjectSet {
  namespace: string;
  object: string;
  relation: string;
}

export interface Tuple {
  namespace: string;
  object: string;
  relation: string;
  subject_id?: string;
  subject_set?: SubjectSet;
}

/**
 * A role with open resource names is a different role per resource tuple,
 * because its grants point at different resources. The resources are in the
 * object id so a membership edge names exactly one of them.
 */
/** How an instance object writes its resources: `<role>@<name>=<id>,<name>=<id>`. No role name, resource name or id holds one. */
const Instance = { resources: '@', between: ',', is: '=' } as const;

export const roleObject = (name: string, resources: Record<string, string> = {}): string => {
  const entries = Object.entries(resources).sort(([a], [b]) => a.localeCompare(b));
  return entries.length === 0
    ? name
    : `${name}${Instance.resources}${entries.map(([k, v]) => `${k}${Instance.is}${v}`).join(Instance.between)}`;
};

/** A role instance object read back into the role and the resources it stands for. */
export const parseInstance = (object: string): { role: string; resources: Record<string, string> } => {
  const at = object.indexOf(Instance.resources);
  if (at < 0) return { role: object, resources: {} };
  const resources: Record<string, string> = {};
  for (const pair of object.slice(at + Instance.resources.length).split(Instance.between)) {
    const eq = pair.indexOf(Instance.is);
    if (eq > 0) resources[pair.slice(0, eq)] = pair.slice(eq + Instance.is.length);
  }
  return { role: object.slice(0, at), resources };
};

const idsFor = (resourceName: string, named: ResourceSet): string[] =>
  (Array.isArray(named) ? named : [named]).map((id) => resourceObject(resourceName, id === ALL ? TYPE_WIDE : id));

export function materializeRole(
  name: string,
  role: RoleDocument,
  index: PermissionIndex,
  resources: Record<string, string> = {},
): Tuple[] {
  const subject_set: SubjectSet = { namespace: ROLE_NAMESPACE, object: roleObject(name, resources), relation: MEMBERS };
  const seen = new Set<string>();
  const tuples: Tuple[] = [];

  for (const grant of role.grants) {
    const permission = index.get(grant.permission)!;
    const namespace = ketoNamespace(serviceOf(grant.permission));
    const named = grantResources(grant, permission);
    const followed = new Set(permission.followsAssignment ?? []);

    const objectsOf = (type: string): string[] => {
      const resourceName = permission.resourceNames[type];
      const set = resourceName === undefined ? undefined : (named.get(resourceName) ?? resources[resourceName]);
      if (resourceName !== undefined && set !== undefined) return idsFor(resourceName, set);
      if (followed.has(type)) return [];
      throw new Error(`${name}: ${grant.permission} leaves ${type} unresolved`);
    };

    // The first group is what the gateway checks: the singleton when the
    // permission's path binds no id, otherwise one object per bound type per
    // id. The rest are the resources the operation may then touch, which
    // reach the caller as scope; they carry the same relation, so holding one
    // is what it means to see it.
    const checked = permission.bound.length === 0 ? [SINGLETON] : permission.bound.flatMap(objectsOf);
    const scoped = permission.scopedBy.filter((type) => !permission.bound.includes(type)).flatMap(objectsOf);

    for (const object of [...checked, ...scoped]) {
      const key = `${namespace} ${object} ${permission.relation}`;
      if (seen.has(key)) continue;
      seen.add(key);
      tuples.push({ namespace: namespace!, object, relation: permission.relation, subject_set });
    }
  }
  return tuples;
}

export const membership = (name: string, subject: string, resources: Record<string, string> = {}): Tuple => ({
  namespace: ROLE_NAMESPACE,
  object: roleObject(name, resources),
  relation: MEMBERS,
  subject_id: subject,
});

/**
 * Everything a role file asks for. A role with open resource names produces
 * nothing on its own; it materializes once per assignment, against that
 * assignment's instance.
 */
export function materialize(file: RolesFile, index: PermissionIndex): Tuple[] {
  const tuples: Tuple[] = [];
  for (const [name, role] of Object.entries(file.roles)) {
    if (openResourceNames(role, index).length === 0) tuples.push(...materializeRole(name, role, index));
  }
  for (const assignment of file.assignments ?? []) {
    const role = file.roles[assignment.role]!;
    const resources = assignment.resources ?? {};
    if (openResourceNames(role, index).length > 0) {
      tuples.push(...materializeRole(assignment.role, role, index, resources));
    }
    tuples.push(membership(assignment.role, assignment.subject, resources));
  }
  return tuples;
}
