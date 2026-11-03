import type { AssignmentChanged, RoleSave } from '../changes';
import type { Role, Subject } from '../client';

export type { Assignment, Localized, Role, RoleSpec, Subject } from '../client';
export { AssignmentChangeKind, type AssignmentChanged, type RoleSave } from '../changes';
export { CssVar, Part } from '../styling';

export const ElementTag = {
  roles: 'iam-roles',
  subjects: 'iam-subjects',
  roleEditor: 'iam-role-editor',
  assignmentEditor: 'iam-assignment-editor',
} as const;
export type ElementTag = (typeof ElementTag)[keyof typeof ElementTag];

/** What the elements dispatch: bubbling, composed `CustomEvent`s carrying their data in `detail`. */
export const IamEvent = {
  roleOpen: 'role-open',
  subjectOpen: 'subject-open',
  roleSaved: 'role-saved',
  roleDeleted: 'role-deleted',
  assignmentChanged: 'assignment-changed',
  beforeSave: 'before-save',
} as const;
export type IamEvent = (typeof IamEvent)[keyof typeof IamEvent];

/**
 * Where opening a role or a subject leads: `events` tells the host, which
 * routes; `internal` switches between the list and the editor in the element.
 */
export const Navigation = { events: 'events', internal: 'internal' } as const;
export type Navigation = (typeof Navigation)[keyof typeof Navigation];

/**
 * The attributes each element reads; every one is also a property. A boolean
 * attribute is on when present, unless its value is `false`.
 */
export const Attribute = {
  apiBase: 'api-base',
  language: 'language',
  navigation: 'navigation',
  roleName: 'role-name',
  subject: 'subject',
  readOnly: 'read-only',
  allowCreate: 'allow-create',
  allowOpen: 'allow-open',
  allowDelete: 'allow-delete',
  canAssign: 'can-assign',
  canUnassign: 'can-unassign',
  pageSize: 'page-size',
} as const;
export type Attribute = (typeof Attribute)[keyof typeof Attribute];

export interface RoleOpenDetail {
  /** The name of the role to open; absent opens a new one to compose. */
  roleName?: string;
}

export interface SubjectOpenDetail {
  subject: Subject;
}

export interface RoleSavedDetail {
  role: Role;
  created: boolean;
}

export interface RoleDeletedDetail {
  roleName: string;
}

export type AssignmentChangedDetail = AssignmentChanged;

/**
 * Cancellable: `preventDefault()` keeps the role unsent. The detail is a frozen
 * copy of what will be sent, so a listener can only veto it, never change it.
 */
export type BeforeSaveDetail = Readonly<RoleSave>;

export interface IamEventMap {
  [IamEvent.roleOpen]: CustomEvent<RoleOpenDetail>;
  [IamEvent.subjectOpen]: CustomEvent<SubjectOpenDetail>;
  [IamEvent.roleSaved]: CustomEvent<RoleSavedDetail>;
  [IamEvent.roleDeleted]: CustomEvent<RoleDeletedDetail>;
  [IamEvent.assignmentChanged]: CustomEvent<AssignmentChangedDetail>;
  [IamEvent.beforeSave]: CustomEvent<BeforeSaveDetail>;
}
