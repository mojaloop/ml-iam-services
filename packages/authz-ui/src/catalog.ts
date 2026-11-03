import type { CatalogPermission, ServiceCatalog } from './client';

export interface Offered {
  permission: CatalogPermission;
  service: ServiceCatalog;
}

/** Every permission the catalog offers, by the id grants name it with. */
export function indexCatalog(catalog: ServiceCatalog[]): Map<string, Offered> {
  const index = new Map<string, Offered>();
  for (const service of catalog) {
    for (const permission of service.permissions) index.set(permission.id, { permission, service });
  }
  return index;
}

/** The resource names a grant of this permission speaks in: one per type the operation is scoped by. */
export function scopingResourceNames(permission: CatalogPermission): string[] {
  const names: string[] = [];
  for (const type of permission.scopedBy) {
    const name = permission.resourceNames[type];
    if (name !== undefined && !names.includes(name)) names.push(name);
  }
  return names;
}
