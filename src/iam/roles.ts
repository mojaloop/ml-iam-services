import { CatalogPermission, ServiceCatalog } from '../authzgen/types';
import { Exclusion, validateExclusions } from './exclusions';

/**
 * Role documents: the deployment data a role UI or a gitops file produces, and
 * the only thing that ever turns into a grant.
 *
 * A grant names a permission and, per resource name the permission is scoped
 * by, either names the resources (`all`, an id, a list) or leaves the
 * resource name open. Every open one is the assignment's to name, so the
 * role's signature is derived, never declared. Which resource names scope a
 * permission comes from the composed catalog, so the role document repeats
 * nothing the documents already say.
 */

/** The whole resource name: every resource of it, present and future. */
export const ALL = 'all';

/** `all`, one id, or several ids. */
export type ResourceSet = string | string[];

export interface RoleGrant {
  permission: string;
  /** Per resource name: the resources this role fixes. An omitted one is the assignment's to name. */
  resources?: Record<string, ResourceSet>;
}

export interface RoleDocument {
  grants: RoleGrant[];
}

export interface Assignment {
  subject: string;
  role: string;
  resources?: Record<string, string>;
}

export interface RolesFile {
  roles: Record<string, RoleDocument>;
  assignments?: Assignment[];
  /** Permissions this deployment refuses to see in one pair of hands. */
  exclusions?: Exclusion[];
}

export type PermissionIndex = Map<string, CatalogPermission>;

export const indexCatalogs = (catalogs: ServiceCatalog[]): PermissionIndex =>
  new Map(catalogs.flatMap((c) => c.permissions.map((p) => [p.id, p])));

export interface ReadyRoles {
  /** The roles every one of whose services is composed, with their assignments and exclusions. */
  file: RolesFile;
  /** What waits, and for which services. */
  pending: string[];
}

/**
 * Services arrive as their routes do, so a role can name one the deployment
 * has not composed yet. Such a role waits whole, assignments included: half
 * of it would be different access, and possibly a different shape, since
 * which resource names a role leaves open comes from its permissions. An
 * exclusion naming a waiting service waits too; no role holding its missing
 * side is live to break it.
 */
export function readyRoles(file: RolesFile, catalogs: ServiceCatalog[]): ReadyRoles {
  const composed = new Set(catalogs.map((c) => c.service));
  const absent = (ids: string[]): string[] =>
    [...new Set(ids.map((id) => id.split('.')[0]!).filter((service) => !composed.has(service)))].sort();

  const pending: string[] = [];
  const roles: Record<string, RoleDocument> = {};
  for (const [name, role] of Object.entries(file.roles ?? {})) {
    const missing = absent((role.grants ?? []).map((g) => g.permission));
    if (missing.length > 0) pending.push(`role ${name} waits for ${missing.join(', ')}`);
    else roles[name] = role;
  }

  const exclusions = (file.exclusions ?? []).filter((rule) => {
    const missing = absent([...(rule.a ?? []), ...(rule.b ?? [])]);
    if (missing.length > 0) pending.push(`exclusion ${rule.name} waits for ${missing.join(', ')}`);
    return missing.length === 0;
  });

  const assignments = (file.assignments ?? []).filter(
    (a) => file.roles?.[a.role] === undefined || roles[a.role] !== undefined,
  );

  return { file: { roles, assignments, exclusions }, pending };
}

/**
 * The resource names a grant's permission is scoped by, with the resources
 * each resolves to: the grant's own naming, or undefined for the assignment
 * to name.
 */
export const grantResources = (
  grant: RoleGrant,
  permission: CatalogPermission,
): Map<string, ResourceSet | undefined> => {
  const named = new Map<string, ResourceSet | undefined>();
  for (const type of permission.scopedBy) {
    const resourceName = permission.resourceNames[type];
    if (resourceName === undefined) continue;
    if (!named.has(resourceName) || named.get(resourceName) === undefined) {
      named.set(resourceName, grant.resources?.[resourceName]);
    }
  }
  return named;
};

/** The resource names an assignment to this role must name: every one its grants leave open. */
export const openResourceNames = (role: RoleDocument, index: PermissionIndex): string[] => {
  const open = new Set<string>();
  for (const grant of role.grants ?? []) {
    const permission = index.get(grant.permission);
    if (permission === undefined) continue;
    for (const [resourceName, named] of grantResources(grant, permission)) {
      if (named === undefined) open.add(resourceName);
    }
  }
  return [...open].sort();
};

const same = (a: string[], b: string[]): boolean =>
  a.length === b.length && [...a].sort().every((v, i) => v === [...b].sort()[i]);

/** Every way a role document can be wrong, collected into one report. */
export function validateRoles(file: RolesFile, index: PermissionIndex): string[] {
  const problems: string[] = [];

  for (const [name, role] of Object.entries(file.roles ?? {})) {
    if (!Array.isArray(role.grants) || role.grants.length === 0) {
      problems.push(`${name}: has no grants`);
      continue;
    }

    for (const grant of role.grants) {
      const permission = index.get(grant.permission);
      if (permission === undefined) {
        problems.push(`${name}: unknown permission ${grant.permission}`);
        continue;
      }

      const scoped = new Set(Object.values(permission.resourceNames));
      for (const [resourceName, named] of Object.entries(grant.resources ?? {})) {
        if (!scoped.has(resourceName)) {
          problems.push(`${name}: ${grant.permission} names ${resourceName}, which does not scope it`);
          continue;
        }
        for (const id of Array.isArray(named) ? named : [named]) {
          if (typeof id !== 'string' || id.length === 0) {
            problems.push(`${name}: ${grant.permission} names an empty ${resourceName} id`);
          }
        }
      }
    }
  }

  problems.push(...validateExclusions(file, index));

  for (const assignment of file.assignments ?? []) {
    const role = file.roles?.[assignment.role];
    if (role === undefined) {
      problems.push(`assignment for ${assignment.subject}: unknown role ${assignment.role}`);
      continue;
    }
    const expected = openResourceNames(role, index);
    const given = Object.keys(assignment.resources ?? {});
    if (!same(given, expected)) {
      problems.push(
        `assignment for ${assignment.subject}: role ${assignment.role} takes [${expected.join(',')}], got [${given.join(',')}]`,
      );
    }
  }

  return problems;
}
