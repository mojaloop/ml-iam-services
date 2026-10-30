import { ketoNamespace } from '../authzgen/keto-name';
import { ALL, grantResources, openResourceNames, PermissionIndex, ResourceSet, RoleDocument, RolesFile } from './roles';

/**
 * Role documents in, Keto tuples out. Pure, because this is the one place the
 * model's shape is decided and it has to be checkable without a Keto.
 */

export const ROLE_NAMESPACE = 'Role';
export const MEMBERS = 'members';
export const SINGLETON = '__self__';
export const TYPE_WIDE = '__all__';

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
export const roleObject = (name: string, resources: Record<string, string> = {}): string => {
  const entries = Object.entries(resources).sort(([a], [b]) => a.localeCompare(b));
  return entries.length === 0 ? name : `${name}@${entries.map(([k, v]) => `${k}=${v}`).join(',')}`;
};

/** A role instance object read back into the role and the resources it stands for. */
export const parseInstance = (object: string): { role: string; resources: Record<string, string> } => {
  const at = object.indexOf('@');
  if (at < 0) return { role: object, resources: {} };
  const resources: Record<string, string> = {};
  for (const pair of object.slice(at + 1).split(',')) {
    const eq = pair.indexOf('=');
    if (eq > 0) resources[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
  return { role: object.slice(0, at), resources };
};

const idsFor = (resourceName: string, named: ResourceSet): string[] => {
  const ids = Array.isArray(named) ? named : [named];
  return ids.map((id) => (id === ALL ? `${resourceName}/${TYPE_WIDE}` : `${resourceName}/${id}`));
};

export function materializeRole(
  name: string,
  role: RoleDocument,
  index: PermissionIndex,
  resources: Record<string, string> = {},
): Tuple[] {
  const subject_set: SubjectSet = {
    namespace: ROLE_NAMESPACE,
    object: roleObject(name, resources),
    relation: MEMBERS,
  };
  const seen = new Set<string>();
  const tuples: Tuple[] = [];

  for (const grant of role.grants) {
    const permission = index.get(grant.permission)!;
    const namespace = ketoNamespace(grant.permission.split('.')[0]!);
    const named = grantResources(grant, permission);

    const objectsOf = (type: string): string[] => {
      const resourceName = permission.resourceNames[type];
      const set = resourceName === undefined ? undefined : (named.get(resourceName) ?? resources[resourceName]);
      if (resourceName === undefined || set === undefined) {
        throw new Error(`${name}: ${grant.permission} leaves ${type} unresolved`);
      }
      return idsFor(resourceName, set);
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
