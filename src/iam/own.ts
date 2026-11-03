import { ResourceName, ResourceNames } from '../authzgen/compose';
import { ServiceCatalog } from '../authzgen/types';
import { Provisioner } from './provisioner';

/**
 * The IAM's own resources: the roles it applies and the permissions it
 * composes, under the resource names the deployment gave its document's
 * `roles` and `permissions` types. They are the IAM's to know, so it records
 * them itself every time either changes.
 */
/** The resource types the IAM's public document declares itself. */
export const OwnType = { roles: 'roles', permissions: 'permissions' } as const;
export type OwnType = (typeof OwnType)[keyof typeof OwnType];

const ownNamesOf = (catalog: ServiceCatalog[], prefix: string): { role?: string; permission?: string } => {
  const own = catalog.find((c) => c.service === prefix);
  const nameOf = (type: OwnType): string | undefined =>
    own?.permissions.map((p) => p.resourceNames[type]).find((name) => name !== undefined);
  const role = nameOf(OwnType.roles);
  const permission = nameOf(OwnType.permissions);
  return { ...(role !== undefined ? { role } : {}), ...(permission !== undefined ? { permission } : {}) };
};

/** The resource name the deployment gave the IAM's roles. */
export const ownRoleName = (catalog: ServiceCatalog[], prefix: string | undefined): string | undefined =>
  prefix === undefined ? undefined : ownNamesOf(catalog, prefix).role;

/** The resource names the deployment gave the IAM's roles and permissions, whose ids are deployment data. */
export const ownNames = (catalog: ServiceCatalog[], prefix: string | undefined): Set<string> =>
  prefix === undefined ? new Set() : new Set(Object.values(ownNamesOf(catalog, prefix)));

/** A resource name as the IAM serves it: `own` when its ids are deployment data a role may name. */
export type ServedResourceName = ResourceName & { own?: true };

export const servedNames = (names: ResourceNames, own: ReadonlySet<string>): Record<string, ServedResourceName> =>
  Object.fromEntries(
    Object.entries(names.resourceNames ?? {}).map(([name, declared]) => [name, own.has(name) ? { ...declared, own: true } : declared]),
  );

export function ownResources(catalog: ServiceCatalog[], prefix: string, roles: string[]): Map<string, string[]> {
  const { role, permission } = ownNamesOf(catalog, prefix);
  const wanted = new Map<string, string[]>();
  if (role !== undefined) wanted.set(role, [...new Set(roles)].sort());
  if (permission !== undefined) wanted.set(permission, catalog.flatMap((c) => c.permissions.map((p) => p.id)).sort());
  return wanted;
}

/** Records what is wanted and retires what is no longer, with every role instance over it. */
export async function recordOwn(provisioner: Provisioner, wanted: Map<string, string[]>): Promise<void> {
  for (const [resourceName, ids] of wanted) {
    const held = new Set((await provisioner.resources(resourceName)).map((r) => r.id));
    const keep = new Set(ids);
    await provisioner.provisionAll(resourceName, ids.filter((i) => !held.has(i)));
    await provisioner.deprovisionAll(resourceName, [...held].filter((i) => !keep.has(i)));
  }
}
