import type { Assignment, RoleSpec } from './client';

/** A role about to be sent to the IAM. */
export interface RoleSave {
  name: string;
  spec: RoleSpec;
  /** A new role, rather than a change to the one named. */
  create: boolean;
}

/** What a change the IAM accepted did to a subject's holdings. */
export const AssignmentChangeKind = { assigned: 'assigned', unassigned: 'unassigned' } as const;
export type AssignmentChangeKind = (typeof AssignmentChangeKind)[keyof typeof AssignmentChangeKind];

export interface AssignmentChanged {
  subject: string;
  assignment: Assignment;
  change: AssignmentChangeKind;
}
