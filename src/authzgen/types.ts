/**
 * A resource type the operation is about. `captureIndex` is present when the
 * path binds an id for it, which is what makes the type a checked object.
 * `resourceName` is the deployment's canonical name for the one real thing
 * this spelling is a member of; inside the platform the resource name keys
 * the resource, and the spelling exists only at the service's boundary.
 */
export interface ScopedType {
  type: string;
  param?: string;
  captureIndex?: number;
  resourceName?: string;
}

export interface Permission {
  /** The gateway rule id and catalog key: `<service>.<relation>`. */
  id: string;
  /** What a stored tuple holds and a check asks, inside the service namespace. */
  name: string;
  operationId: string;
  method: string;
  path: string;
  summary?: string;
  deprecated: boolean;
  anonymous: boolean;
  authenticators: string[];
  scopedBy: ScopedType[];
}

export interface ServiceBundle {
  service: string;
  title: string;
  basePath: string;
  permissions: Permission[];
  resourceTypes: string[];
}

/**
 * One entry of the catalog the IAM serves to the role UI. `scopedBy` is what
 * the operation declares and reaches the caller's service; `bound` is the
 * subset the path carries an id for, which is what a check addresses and what
 * a role grant has to bind.
 */
export interface CatalogPermission {
  id: string;
  relation: string;
  operationId: string;
  summary?: string;
  deprecated: boolean;
  method: string;
  path: string;
  scopedBy: string[];
  bound: string[];
  /** The deployment's resource name per scoped type, which is what grants speak in. */
  resourceNames: Record<string, string>;
}

export interface ServiceCatalog {
  service: string;
  title: string;
  basePath: string;
  resourceTypes: string[];
  permissions: CatalogPermission[];
}
