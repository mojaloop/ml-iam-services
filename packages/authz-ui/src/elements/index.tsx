import { IamElement } from './element';
import { Attribute, ElementTag, Navigation } from './names';
import { AssignmentEditorView, RoleEditorView, RolesView, SubjectsView } from './views';

export type { Fetch } from './element';
export { IamElement } from './element';
export * from './names';
export type { Messages } from '../react/messages';

const navigationOf = (element: HTMLElement): Navigation =>
  element.getAttribute(Attribute.navigation) === Navigation.internal ? Navigation.internal : Navigation.events;

/** `<iam-roles>`: every role, composing, changing and deleting them. */
export class IamRolesElement extends IamElement {
  static override readonly observedAttributes: readonly string[] = [
    ...IamElement.observedAttributes,
    Attribute.navigation,
    Attribute.readOnly,
    Attribute.allowCreate,
    Attribute.allowOpen,
    Attribute.allowDelete,
  ];

  get navigation(): Navigation {
    return navigationOf(this);
  }

  set navigation(value: Navigation) {
    this.setAttribute(Attribute.navigation, value);
  }

  /** The roles that exist are shown, not changed; composing a new one is `allowCreate`'s to offer. */
  get readOnly(): boolean {
    return this.flag(Attribute.readOnly, false);
  }

  set readOnly(value: boolean) {
    this.setFlag(Attribute.readOnly, value);
  }

  /** Offer composing a new role. */
  get allowCreate(): boolean {
    return this.flag(Attribute.allowCreate, true);
  }

  set allowCreate(value: boolean) {
    this.setFlag(Attribute.allowCreate, value);
  }

  /** Offer opening a role, which reads it by its name. */
  get allowOpen(): boolean {
    return this.flag(Attribute.allowOpen, true);
  }

  set allowOpen(value: boolean) {
    this.setFlag(Attribute.allowOpen, value);
  }

  /** Offer deleting an opened role. */
  get allowDelete(): boolean {
    return this.flag(Attribute.allowDelete, false);
  }

  set allowDelete(value: boolean) {
    this.setFlag(Attribute.allowDelete, value);
  }

  protected view(): unknown {
    return (
      <RolesView
        navigation={this.navigation}
        readOnly={this.readOnly}
        allowCreate={this.allowCreate}
        allowOpen={this.allowOpen}
        allowDelete={this.allowDelete}
        language={this.language}
        emit={this.emit}
      />
    );
  }
}

/** `<iam-subjects>`: the people and machine clients, opening one into the roles it holds. */
export class IamSubjectsElement extends IamElement {
  static override readonly observedAttributes: readonly string[] = [
    ...IamElement.observedAttributes,
    Attribute.navigation,
    Attribute.canAssign,
    Attribute.canUnassign,
    Attribute.pageSize,
  ];

  get navigation(): Navigation {
    return navigationOf(this);
  }

  set navigation(value: Navigation) {
    this.setAttribute(Attribute.navigation, value);
  }

  /** Offer assigning a role to an opened subject. */
  get canAssign(): boolean {
    return this.flag(Attribute.canAssign, true);
  }

  set canAssign(value: boolean) {
    this.setFlag(Attribute.canAssign, value);
  }

  /** Offer taking an assigned role away from an opened subject. */
  get canUnassign(): boolean {
    return this.flag(Attribute.canUnassign, true);
  }

  set canUnassign(value: boolean) {
    this.setFlag(Attribute.canUnassign, value);
  }

  /** How many subjects a page shows. */
  get pageSize(): number | undefined {
    const value = this.getAttribute(Attribute.pageSize);
    return value === null ? undefined : Number(value);
  }

  set pageSize(value: number | undefined) {
    this.setText(Attribute.pageSize, value === undefined ? undefined : String(value));
  }

  protected view(): unknown {
    return (
      <SubjectsView
        navigation={this.navigation}
        canAssign={this.canAssign}
        canUnassign={this.canUnassign}
        pageSize={this.pageSize}
        language={this.language}
        emit={this.emit}
      />
    );
  }
}

/** `<iam-role-editor role-name="…">`: one role changed, or a new one composed when `role-name` is absent. */
export class IamRoleEditorElement extends IamElement {
  static override readonly observedAttributes: readonly string[] = [
    ...IamElement.observedAttributes,
    Attribute.roleName,
    Attribute.readOnly,
    Attribute.allowDelete,
  ];

  /** The name of the role to change. */
  get roleName(): string | null {
    return this.getAttribute(Attribute.roleName);
  }

  set roleName(value: string | null) {
    this.setText(Attribute.roleName, value ?? undefined);
  }

  /** The role is shown, not changed. */
  get readOnly(): boolean {
    return this.flag(Attribute.readOnly, false);
  }

  set readOnly(value: boolean) {
    this.setFlag(Attribute.readOnly, value);
  }

  /** Offer deleting the role. */
  get allowDelete(): boolean {
    return this.flag(Attribute.allowDelete, false);
  }

  set allowDelete(value: boolean) {
    this.setFlag(Attribute.allowDelete, value);
  }

  protected view(): unknown {
    const roleName = this.roleName ?? undefined;
    return (
      <RoleEditorView
        key={roleName}
        role={roleName}
        readOnly={this.readOnly}
        allowDelete={this.allowDelete}
        language={this.language}
        emit={this.emit}
      />
    );
  }
}

/** `<iam-assignment-editor subject="…">`: what one subject holds, assigning and taking away roles. */
export class IamAssignmentEditorElement extends IamElement {
  static override readonly observedAttributes: readonly string[] = [
    ...IamElement.observedAttributes,
    Attribute.subject,
    Attribute.canAssign,
    Attribute.canUnassign,
  ];

  /** A person's identity id or a machine client's id. Nothing renders until it is set. */
  get subject(): string {
    return this.getAttribute(Attribute.subject) ?? '';
  }

  set subject(value: string) {
    this.setAttribute(Attribute.subject, value);
  }

  get canAssign(): boolean {
    return this.flag(Attribute.canAssign, true);
  }

  set canAssign(value: boolean) {
    this.setFlag(Attribute.canAssign, value);
  }

  get canUnassign(): boolean {
    return this.flag(Attribute.canUnassign, true);
  }

  set canUnassign(value: boolean) {
    this.setFlag(Attribute.canUnassign, value);
  }

  protected view(): unknown {
    const subject = this.subject;
    if (subject === '') return null;
    return (
      <AssignmentEditorView
        key={subject}
        subject={subject}
        canAssign={this.canAssign}
        canUnassign={this.canUnassign}
        language={this.language}
        emit={this.emit}
      />
    );
  }
}

const elements = [
  [ElementTag.roles, IamRolesElement],
  [ElementTag.subjects, IamSubjectsElement],
  [ElementTag.roleEditor, IamRoleEditorElement],
  [ElementTag.assignmentEditor, IamAssignmentEditorElement],
] as const;

/** Registers the elements under their tags; a tag already registered keeps what it has, so calling it again is harmless. */
export function defineIamElements(registry: CustomElementRegistry = customElements): void {
  for (const [tag, element] of elements) {
    if (registry.get(tag) === undefined) registry.define(tag, element);
  }
}

declare global {
  interface HTMLElementTagNameMap {
    [ElementTag.roles]: IamRolesElement;
    [ElementTag.subjects]: IamSubjectsElement;
    [ElementTag.roleEditor]: IamRoleEditorElement;
    [ElementTag.assignmentEditor]: IamAssignmentEditorElement;
  }
}
