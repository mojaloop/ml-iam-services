/**
 * The words the IAM's processes and their callers exchange, named once: what
 * its documents call their operations, parameters and types, and what its
 * HTTP exchanges carry.
 */

/** The public operations whose scope a handler reads, by operationId. */
export const Operation = {
  listResources: 'listResources',
  createRole: 'createRole',
  updateRole: 'updateRole',
  assignRole: 'assignRole',
  unassignRole: 'unassignRole',
} as const;
export type Operation = (typeof Operation)[keyof typeof Operation];

/** The path and query parameters the IAM's documents declare. */
export const Param = { subject: 'subject', role: 'role', resourceName: 'resourceName' } as const;

/** The controller's API, as the api process calls it. */
export const ControllerPath = { composition: '/composition', assignments: '/assignments', resources: '/resources' } as const;
export type ControllerPath = (typeof ControllerPath)[keyof typeof ControllerPath];

/** What the api process asks the controller: the writes it hands over, and the listing only the controller reads. */
export const Method = { get: 'GET', post: 'POST', delete: 'DELETE' } as const;
export type Method = (typeof Method)[keyof typeof Method];

export const Header = {
  accept: 'accept',
  ifNoneMatch: 'if-none-match',
  etag: 'etag',
  contentType: 'content-type',
  staleSources: 'stale-sources',
  /** Marks a request one controller replica handed to the one it saw leading, which never hands it on again. */
  forwarded: 'x-iam-forwarded',
} as const;

export const JSON_MEDIA = 'application/json';

/** Who keeps a role: the IAM, which composed it through its API, or the deployment. */
export const Owner = { iam: 'iam', deployment: 'deployment' } as const;

/** How a subject holds a role: assigned, or as every signed-in subject does. */
export const Through = { assigned: 'assigned', authenticated: 'authenticated' } as const;

/** The key the controller announces the composition's ETag under, in the ConfigMap the api process watches. */
export const ANNOUNCED_ETAG = 'etag';

/** The event `GET /changes` sends each time the IAM applies a change. */
export const COMPOSITION_EVENT = 'composition';

export const HEALTHY = { status: 'ok' } as const;
