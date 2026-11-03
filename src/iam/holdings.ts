import { ketoNamespace } from '../authzgen/keto-name';
import { serviceOf } from '../authzgen/permission';
import { KetoReads } from './keto';
import { AUTHENTICATED, HELD_BY, materializeRole, MEMBERS, ROLE_NAMESPACE, SINGLETON, Tuple } from './materialize';
import { parseResource, reachesResource } from './registry';
import { ALL, followedNames, grantResources, PermissionIndex, ResourceSet, RoleDocument, RoleGrant } from './roles';

/**
 * What one subject holds, one entry per role instance: the ones they are a
 * member of and every role all authenticated subjects hold. Grants written
 * straight to a subject are a violation the decision reports, never a
 * holding.
 */
export type Holders = Tuple[][];

export async function holdersOf(keto: KetoReads, subject: string): Promise<Holders> {
  const [memberships, everyone, modelled] = await Promise.all([
    keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS, subject_id: subject }),
    keto.query({ namespace: ROLE_NAMESPACE, relation: HELD_BY, subject_id: AUTHENTICATED }),
    keto.namespaces(),
  ]);
  const instances = [...new Set([...memberships, ...everyone].map((t) => t.object))];
  const known = new Set(modelled);
  return Promise.all(instances.map((instance) => keto.grantsOf(instance, known)));
}

const covers = (holder: Tuple[], wanted: Tuple): boolean => {
  const resource = parseResource(wanted.object);
  return holder.some(
    (t) =>
      t.namespace === wanted.namespace &&
      t.relation === wanted.relation &&
      (t.object === wanted.object ||
        (resource !== undefined && reachesResource(parseResource(t.object), resource.resourceName, resource.id))),
  );
};

const product = (sets: Array<[string, string[]]>): Array<Record<string, string>> =>
  sets.reduce<Array<Record<string, string>>>(
    (combinations, [resourceName, ids]) =>
      combinations.flatMap((combination) => ids.map((id) => ({ ...combination, [resourceName]: id }))),
    [{}],
  );

/**
 * A grant's resources, each one it leaves open set to what fills it, or to
 * every resource of its name. A name `$resources` brought in that nothing
 * fills reaches nothing, so it is left out.
 */
const filled = (grant: RoleGrant, index: PermissionIndex, fill: Record<string, string>): Record<string, ResourceSet> => {
  const permission = index.get(grant.permission)!;
  const followed = followedNames(permission);
  const resources: Record<string, ResourceSet> = {};
  for (const [resourceName, named] of grantResources(grant, permission)) {
    const set = named ?? fill[resourceName] ?? (followed.has(resourceName) ? undefined : ALL);
    if (set !== undefined) resources[resourceName] = set;
  }
  return resources;
};

/**
 * Whether the subject holds a permission over these resources. Each
 * combination of one resource per resource name has to be held through a
 * single role instance, as the decision admits a request through one: two
 * instances over different halves of a combination do not add up to it.
 */
export function holdsOver(
  permission: string,
  resources: Record<string, ResourceSet>,
  index: PermissionIndex,
  holders: Holders,
): boolean {
  const sets = Object.entries(resources).map(([name, set]): [string, string[]] => [name, Array.isArray(set) ? set : [set]]);
  return product(sets).every((combination) => {
    const wanted = materializeRole('', { grants: [{ permission, resources: combination }] }, index);
    return holders.some((holder) => wanted.every((tuple) => covers(holder, tuple)));
  });
}

const over = (resources: Record<string, ResourceSet>): string => {
  const named = Object.entries(resources).map(([name, set]) => `${name}=${Array.isArray(set) ? set.join(',') : set}`);
  return named.length === 0 ? '' : ` over ${named.join(' and ')}`;
};

/** The roles or permissions a caller's scope names, or every one. */
export type Named = typeof ALL | string[];

/** What a caller's scope for one operation reaches of each resource name. */
export type Reach = Record<string, Named>;

const names = (scope: Named, name: string): boolean => scope === ALL || scope.includes(name);

/** Whether a scope reaches these resources: `$all` only through a scope of every one. */
const scopeReaches = (scope: Named | undefined, set: ResourceSet): boolean =>
  scope === ALL || (scope !== undefined && (Array.isArray(set) ? set : [set]).every((id) => id !== ALL && scope.includes(id)));

/**
 * Whether the subject holds a permission over the resources a grant fixes,
 * through one role instance for each combination of them, and over some
 * resource of every name the grant leaves for its assignment.
 */
function holdsWhatIsFixed(
  permission: string,
  fixed: Record<string, ResourceSet>,
  open: string[],
  index: PermissionIndex,
  holders: Holders,
): boolean {
  const catalog = index.get(permission)!;
  const namespace = ketoNamespace(serviceOf(permission));
  const sets = Object.entries(fixed).map(([name, set]): [string, string[]] => [name, Array.isArray(set) ? set : [set]]);
  return product(sets).every((combination) =>
    holders.some((holder) => {
      const mine = holder.filter((t) => t.namespace === namespace && t.relation === catalog.relation);
      const held = mine.map((t) => parseResource(t.object));
      return (
        (catalog.bound.length > 0 || mine.some((t) => t.object === SINGLETON)) &&
        Object.entries(combination).every(([name, id]) => held.some((resource) => reachesResource(resource, name, id))) &&
        open.every((name) => held.some((resource) => resource?.resourceName === name))
      );
    }),
  );
}

/**
 * Writing a role: every grant in it is one the writer holds over the
 * resources it fixes, or one whose permission the writer's scope names, fixed
 * no wider than their scope reaches of each resource name. A name the grant
 * leaves for the assignment passes either way: it reaches nothing until an
 * assignment names it, and whoever assigns answers for that.
 */
export function writeProblems(
  role: RoleDocument,
  index: PermissionIndex,
  holders: Holders,
  scope: { permissions: Named; reach: Reach },
): string[] {
  return role.grants
    .filter((grant) => index.has(grant.permission))
    .flatMap((grant) => {
      const permission = index.get(grant.permission)!;
      const followed = followedNames(permission);
      const fixed: Record<string, ResourceSet> = {};
      const open: string[] = [];
      for (const [resourceName, named] of grantResources(grant, permission)) {
        if (named !== undefined) fixed[resourceName] = named;
        else if (!followed.has(resourceName)) open.push(resourceName);
      }
      if (holdsWhatIsFixed(grant.permission, fixed, open, index, holders)) return [];
      if (!names(scope.permissions, grant.permission)) {
        return [`you do not hold ${grant.permission}${over(fixed)}, and your scope does not name it`];
      }
      const beyond = Object.fromEntries(Object.entries(fixed).filter(([name, set]) => !scopeReaches(scope.reach[name], set)));
      return Object.keys(beyond).length === 0 ? [] : [`your scope names ${grant.permission}, and does not reach${over(beyond)}`];
    });
}

/**
 * Handing out a role over these resources: the hander's scope names the role,
 * whatever they hold, and reaches every resource the assignment names, or
 * they hold everything the role then gives over the ones it does not reach.
 */
export function assignProblems(
  name: string,
  role: RoleDocument,
  resources: Record<string, string>,
  index: PermissionIndex,
  holders: Holders,
  scope: { roles: Named; reach: Reach },
): string[] {
  if (!names(scope.roles, name)) return [`your scope does not name ${name}`];
  const beyond = Object.fromEntries(
    Object.entries(resources).filter(([resourceName, id]) => !scopeReaches(scope.reach[resourceName], id)),
  );
  if (Object.keys(beyond).length === 0) return [];
  return role.grants
    .filter((grant) => index.has(grant.permission))
    .flatMap((grant) => {
      const reached = filled(grant, index, resources);
      if (holdsOver(grant.permission, reached, index, holders)) return [];
      return [`${name} gives ${grant.permission}${over(reached)}, which you do not hold, and your scope does not reach${over(beyond)}`];
    });
}

export interface PermissionHeld {
  permission: string;
  held: boolean;
  /** Per resource name the permission is scoped by, the ids held, or `$all`. */
  resources?: Record<string, typeof ALL | string[]>;
}

/** Which resources of a permission the subject holds, as a UI asks before showing what it may do. */
export function heldPermission(id: string, index: PermissionIndex, holders: Holders): PermissionHeld {
  const permission = index.get(id);
  if (permission === undefined) return { permission: id, held: false };
  const namespace = ketoNamespace(serviceOf(id));
  const tuples = holders.flat().filter((t) => t.namespace === namespace && t.relation === permission.relation);
  const objects = tuples.map((t) => parseResource(t.object)).filter((o) => o !== undefined);
  const bound = permission.bound.map((type) => permission.resourceNames[type]!);
  const held =
    bound.length === 0
      ? tuples.some((t) => t.object === SINGLETON)
      : objects.some((o) => bound.includes(o.resourceName));
  if (!held || permission.scopedBy.length === 0) return { permission: id, held };

  const resources: Record<string, typeof ALL | string[]> = {};
  for (const name of new Set(Object.values(permission.resourceNames))) {
    const ids = objects.filter((o) => o.resourceName === name).map((o) => o.id);
    resources[name] = ids.includes(ALL) ? ALL : [...new Set(ids)].sort();
  }
  return { permission: id, held, resources };
}
