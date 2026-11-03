/** The query keys the hooks use, for an app that reads or invalidates them itself. */
export const authzKeys = {
  all: ['authz'] as const,
  catalog: ['authz', 'catalog'] as const,
  resourceNames: ['authz', 'resource-names'] as const,
  resources: (resourceName?: string) => ['authz', 'resources', resourceName ?? null] as const,
  roles: ['authz', 'roles'] as const,
  role: (role: string) => ['authz', 'roles', role] as const,
  subjects: ['authz', 'subjects'] as const,
  assignments: ['authz', 'assignments'] as const,
  assignmentsOf: (subject: string) => ['authz', 'assignments', subject] as const,
  state: ['authz', 'state'] as const,
};

/** What a change to the composition can change: everything but assignments, which are not part of it. */
export const composed = [authzKeys.catalog, authzKeys.resourceNames, authzKeys.roles, authzKeys.state];
