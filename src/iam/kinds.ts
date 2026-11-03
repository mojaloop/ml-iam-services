/** The API group of the IAM's kinds. */
export const GROUP = 'iam.mojaloop.io';
export const VERSION = 'v1';
export const API_VERSION = `${GROUP}/${VERSION}`;

/** The name the IAM signs what it writes into the cluster with. */
export const COMPONENT = 'ml-iam-services';

/** The label on every object the IAM writes itself. */
export const MANAGED_BY: Record<string, string> = { 'app.kubernetes.io/managed-by': COMPONENT };

/** The IAM's kinds. */
export const Kind = {
  document: 'AuthzDocument',
  role: 'AuthzRole',
  separation: 'AuthzSeparation',
  resourceName: 'AuthzResourceName',
} as const;
export type Kind = (typeof Kind)[keyof typeof Kind];

/** The kinds whose objects carry a verdict the IAM writes. */
export type VerdictKind = typeof Kind.role | typeof Kind.separation;
