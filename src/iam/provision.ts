import { Tuple } from './materialize';
import { registryTuple } from './registry';

/**
 * A service that creates a resource records only that it exists, keyed by
 * the resource name the deployment configured into it. Who holds which role
 * over it arrives as ordinary assignments, carrying role names from the same
 * configuration.
 */

export interface ProvisionRequest {
  resourceName: string;
  id: string;
}

export function provision(resourceName: string, id: string): Tuple[] {
  // Recorded whether or not any role covers it, because being grantable
  // later is the point of saying it exists at all.
  return [registryTuple(resourceName, id)];
}
