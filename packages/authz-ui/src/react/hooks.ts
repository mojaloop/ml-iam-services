import {
  type QueryClient,
  useMutation,
  type UseMutationResult,
  useQuery,
  useQueryClient,
  type UseQueryResult,
} from '@tanstack/react-query';
import { useEffect } from 'react';

import type {
  Assignment,
  Held,
  Instance,
  NewRole,
  ResourceName,
  Resources,
  Role,
  RoleSpec,
  ServiceCatalog,
  State,
  Subject,
} from '../client';
import { useAuthz } from './context';
import { authzKeys } from './keys';

export { authzKeys };

/**
 * Keeps what the IAM applied current while mounted: the catalog, the roles
 * with their verdicts, and what waits are read again each time the IAM's
 * change stream reports a change. Every component using it shares one stream.
 */
export function useLiveComposition(): void {
  const { live } = useAuthz();
  useEffect(() => live.hold(), [live]);
}

export const useCatalog = (): UseQueryResult<ServiceCatalog[]> => {
  const { client } = useAuthz();
  return useQuery({ queryKey: authzKeys.catalog, queryFn: ({ signal }) => client.getCatalog({ signal }) });
};

export const useResourceNames = (): UseQueryResult<Record<string, ResourceName>> => {
  const { client } = useAuthz();
  return useQuery({
    queryKey: authzKeys.resourceNames,
    queryFn: ({ signal }) => client.getResourceNames({ signal }),
  });
};

/** The resources that exist, of one resource name or all of them, and which names were answered from a stale read. */
export const useResources = (resourceName?: string): UseQueryResult<Resources> => {
  const { client } = useAuthz();
  return useQuery({
    queryKey: authzKeys.resources(resourceName),
    queryFn: ({ signal }) => client.listResources(resourceName, { signal }),
  });
};

export const useRoles = (): UseQueryResult<Role[]> => {
  const { client } = useAuthz();
  return useQuery({ queryKey: authzKeys.roles, queryFn: ({ signal }) => client.listRoles({ signal }) });
};

export const useRole = (role: string | undefined): UseQueryResult<Role> => {
  const { client } = useAuthz();
  return useQuery({
    queryKey: authzKeys.role(role ?? ''),
    queryFn: ({ signal }) => client.getRole(role as string, { signal }),
    enabled: role !== undefined,
  });
};

export const useSubjects = (): UseQueryResult<Subject[]> => {
  const { client } = useAuthz();
  return useQuery({ queryKey: authzKeys.subjects, queryFn: ({ signal }) => client.listSubjects({ signal }) });
};

/** What one subject holds, the roles every signed-in subject holds included. */
export const useAssignments = (subject: string | undefined): UseQueryResult<Held[]> => {
  const { client } = useAuthz();
  return useQuery({
    queryKey: authzKeys.assignmentsOf(subject ?? ''),
    queryFn: ({ signal }) => client.getAssignments(subject as string, { signal }),
    enabled: subject !== undefined,
  });
};

export const useIamState = (): UseQueryResult<State> => {
  const { client } = useAuthz();
  return useQuery({ queryKey: authzKeys.state, queryFn: ({ signal }) => client.getState({ signal }) });
};

const invalidate = (queries: QueryClient, ...keys: ReadonlyArray<readonly unknown[]>) =>
  Promise.all(keys.map((queryKey) => queries.invalidateQueries({ queryKey })));

export const useCreateRole = (): UseMutationResult<Role, Error, NewRole> => {
  const { client } = useAuthz();
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (role: NewRole) => client.createRole(role),
    onSuccess: () => invalidate(queries, authzKeys.roles, authzKeys.state),
  });
};

export const useUpdateRole = (): UseMutationResult<Role, Error, { role: string; spec: RoleSpec }> => {
  const { client } = useAuthz();
  const queries = useQueryClient();
  return useMutation({
    mutationFn: ({ role, spec }: { role: string; spec: RoleSpec }) => client.updateRole(role, spec),
    onSuccess: () => invalidate(queries, authzKeys.roles, authzKeys.state),
  });
};

export const useDeleteRole = (): UseMutationResult<void, Error, string> => {
  const { client } = useAuthz();
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (role: string) => client.deleteRole(role),
    onSuccess: () =>
      invalidate(queries, authzKeys.roles, authzKeys.assignments, authzKeys.state),
  });
};

export interface AssignmentChange {
  subject: string;
  assignment: Assignment;
}

export const useAssignRole = (): UseMutationResult<Instance, Error, AssignmentChange> => {
  const { client } = useAuthz();
  const queries = useQueryClient();
  return useMutation({
    mutationFn: ({ subject, assignment }: AssignmentChange) => client.assignRole(subject, assignment),
    onSuccess: (_, { subject }) => invalidate(queries, authzKeys.assignmentsOf(subject), authzKeys.state),
  });
};

export const useUnassignRole = (): UseMutationResult<Instance, Error, AssignmentChange> => {
  const { client } = useAuthz();
  const queries = useQueryClient();
  return useMutation({
    mutationFn: ({ subject, assignment }: AssignmentChange) => client.unassignRole(subject, assignment),
    onSuccess: (_, { subject }) => invalidate(queries, authzKeys.assignmentsOf(subject), authzKeys.state),
  });
};
