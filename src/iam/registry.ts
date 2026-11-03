import { ALL, REGISTRY } from '../authzgen/reserved';
import { ResourceInstance, resourceObject } from '../authzgen/resource-object';
import type { Tuple } from './materialize';

/**
 * Which resources exist, keyed by the deployment's resource name.
 *
 * A grant names a resource, so the graph knows every resource somebody can
 * already reach — and nothing about one nobody has been given yet. An operator
 * granting a report the day it is applied needs to be offered it by name, so a
 * resource says it exists when it is provisioned, in the one store the IAM
 * already has.
 *
 * The row grants nothing: it sits in its own namespace, under a relation no
 * rule ever checks, held by a subject that is not a principal. A resource name
 * with a declared source is listed from it when asked, and keeps no row here.
 */

export const RESOURCE_NAMESPACE = 'Resource';
export const EXISTS = 'exists';
export { REGISTRY } from '../authzgen/reserved';
export { parseResource, type ResourceInstance, resourceObject } from '../authzgen/resource-object';

export const registryTuple = (resourceName: string, id: string): Tuple => ({
  namespace: RESOURCE_NAMESPACE,
  object: resourceObject(resourceName, id),
  relation: EXISTS,
  subject_id: REGISTRY,
});

/** Whether a held object reaches this resource: it is the resource, or every one of its name. */
export const reachesResource = (held: ResourceInstance | undefined, resourceName: string, id: string): boolean =>
  held !== undefined && held.resourceName === resourceName && (held.id === id || held.id === ALL);
