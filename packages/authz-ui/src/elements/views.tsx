import { useState } from 'react';

import { Owner, type Role, type Subject } from '../client';
import { AssignmentEditor } from '../react/AssignmentEditor';
import { useAuthz } from '../react/context';
import { useRole } from '../react/hooks';
import { Failure, Loading } from '../react/parts';
import { RoleEditor } from '../react/RoleEditor';
import { RoleList } from '../react/RoleList';
import { SubjectList } from '../react/SubjectList';
import { Part, parts } from '../styling';
import type { Emit } from './element';
import { frozenCopy } from './frozen';
import { IamEvent, Navigation } from './names';

function Toolbar({ onBack, title }: { onBack?: () => void; title?: string }) {
  const { messages } = useAuthz();
  return (
    <div className="authz-toolbar" part={Part.toolbar}>
      {onBack !== undefined && (
        <button type="button" className="authz-button" part={Part.button} onClick={onBack}>
          {messages.back}
        </button>
      )}
      {title !== undefined && (
        <h2 className="authz-toolbar__title" part={Part.heading}>
          {title}
        </h2>
      )}
    </div>
  );
}

export interface RoleEditorViewProps {
  role: string | undefined;
  readOnly: boolean;
  allowDelete: boolean;
  language: string | undefined;
  emit: Emit;
  /** Called when the role is saved or deleted. */
  onDone?(): void;
  onBack?(): void;
}

/** A role read by its name and changed, or a new one composed, telling the host what happened to it. */
export function RoleEditorView({ role, readOnly, allowDelete, language, emit, onDone, onBack }: RoleEditorViewProps) {
  const [created, setCreated] = useState<string>();
  const name = role ?? created;
  const loaded = useRole(name);

  const editor = (shown: Role | undefined) => (
    <RoleEditor
      role={shown}
      readOnly={readOnly}
      allowDelete={allowDelete}
      language={language}
      beforeSave={(save) => emit(IamEvent.beforeSave, frozenCopy(save), true)}
      onSaved={(saved) => {
        emit(IamEvent.roleSaved, { role: saved, created: shown === undefined });
        if (shown === undefined) setCreated(saved.name);
        onDone?.();
      }}
      onDeleted={(deleted) => {
        emit(IamEvent.roleDeleted, { roleName: deleted });
        onDone?.();
      }}
    />
  );

  let content;
  if (name === undefined) content = editor(undefined);
  else if (loaded.isPending) content = <Loading />;
  else if (loaded.isError) content = <Failure error={loaded.error} onRetry={() => void loaded.refetch()} />;
  else content = editor(loaded.data);

  return (
    <>
      {onBack !== undefined && <Toolbar onBack={onBack} />}
      {content}
    </>
  );
}

export interface RolesViewProps {
  navigation: Navigation;
  readOnly: boolean;
  allowCreate: boolean;
  allowOpen: boolean;
  allowDelete: boolean;
  language: string | undefined;
  emit: Emit;
}

/** Every role, opening one or a new one to compose: in the element, or by telling the host. */
export function RolesView({ navigation, readOnly, allowCreate, allowOpen, allowDelete, language, emit }: RolesViewProps) {
  const { messages } = useAuthz();
  const [opened, setOpened] = useState<{ role?: string }>();
  const internal = navigation === Navigation.internal;

  if (internal && opened !== undefined) {
    const back = () => setOpened(undefined);
    return (
      <RoleEditorView
        role={opened.role}
        readOnly={readOnly && opened.role !== undefined}
        allowDelete={allowDelete}
        language={language}
        emit={emit}
        onDone={back}
        onBack={back}
      />
    );
  }

  const open = (role?: string) => {
    if (internal) setOpened(role === undefined ? {} : { role });
    else emit(IamEvent.roleOpen, role === undefined ? {} : { roleName: role });
  };

  return (
    <>
      {allowCreate && (
        <div className="authz-toolbar" part={Part.toolbar}>
          <button
            type="button"
            className="authz-button authz-button--primary"
            part={parts(Part.button, Part.primary)}
            onClick={() => open()}
          >
            {messages.newRole}
          </button>
        </div>
      )}
      <RoleList
        language={language}
        actions={
          allowOpen
            ? (role) => (
                <button type="button" className="authz-button" part={Part.button} onClick={() => open(role.name)}>
                  {!readOnly && role.owner === Owner.iam ? messages.edit : messages.view}
                </button>
              )
            : undefined
        }
      />
    </>
  );
}

export interface AssignmentEditorViewProps {
  subject: string;
  canAssign: boolean;
  canUnassign: boolean;
  language: string | undefined;
  emit: Emit;
}

export function AssignmentEditorView({ subject, canAssign, canUnassign, language, emit }: AssignmentEditorViewProps) {
  return (
    <AssignmentEditor
      subject={subject}
      canAssign={canAssign}
      canUnassign={canUnassign}
      language={language}
      onChanged={(changed) => emit(IamEvent.assignmentChanged, changed)}
    />
  );
}

export interface SubjectsViewProps {
  navigation: Navigation;
  canAssign: boolean;
  canUnassign: boolean;
  pageSize: number | undefined;
  language: string | undefined;
  emit: Emit;
}

/** The people and machine clients, opening one into what it holds: in the element, or by telling the host. */
export function SubjectsView({ navigation, canAssign, canUnassign, pageSize, language, emit }: SubjectsViewProps) {
  const [opened, setOpened] = useState<Subject>();
  const internal = navigation === Navigation.internal;

  if (internal && opened !== undefined) {
    return (
      <>
        <Toolbar onBack={() => setOpened(undefined)} title={opened.name ?? opened.email ?? opened.id} />
        <AssignmentEditorView
          subject={opened.id}
          canAssign={canAssign}
          canUnassign={canUnassign}
          language={language}
          emit={emit}
        />
      </>
    );
  }

  return (
    <SubjectList
      pageSize={pageSize}
      onSelect={(subject) => {
        if (internal) setOpened(subject);
        else emit(IamEvent.subjectOpen, { subject });
      }}
    />
  );
}
