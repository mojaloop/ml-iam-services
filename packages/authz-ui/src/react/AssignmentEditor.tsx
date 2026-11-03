import { type FormEvent, useId, useState } from 'react';

import { AssignmentChangeKind, type AssignmentChanged } from '../changes';
import { type Assignment, type Role, Through } from '../client';
import { Part, parts } from '../styling';
import { useAuthz } from './context';
import { useAssignments, useAssignRole, useRoles, useUnassignRole } from './hooks';
import { cx, Failure, Loading, useResourceNameLabel, useText } from './parts';
import { ResourcePicker } from './ResourcePicker';

export interface AssignmentEditorProps {
  /** A person's identity id or a machine client's id. */
  subject: string;
  /** Whether to offer assigning a role; the IAM decides either way. */
  canAssign?: boolean;
  /** Whether to offer taking an assigned role away; the IAM decides either way. */
  canUnassign?: boolean;
  language?: string;
  /** Called once the IAM has accepted an assignment or its removal. */
  onChanged?(changed: AssignmentChanged): void;
  className?: string;
}

const heldKey = ({ role, resources = {} }: Assignment): string =>
  `${role}|${Object.entries(resources)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, id]) => `${name}=${id}`)
    .join(',')}`;

/** What one subject holds, and assigning or taking away a role over the resources it leaves open. */
export function AssignmentEditor({
  subject,
  canAssign = true,
  canUnassign = true,
  language,
  onChanged,
  className,
}: AssignmentEditorProps) {
  const { messages } = useAuthz();
  const text = useText(language);
  const label = useResourceNameLabel(language);
  const held = useAssignments(subject);
  const roles = useRoles();
  const assign = useAssignRole();
  const unassign = useUnassignRole();
  const [roleName, setRoleName] = useState('');
  const [picked, setPicked] = useState<Record<string, string>>({});
  const roleSelect = useId();

  if (held.isPending || roles.isPending) return <Loading />;
  if (held.isError) return <Failure error={held.error} onRetry={() => void held.refetch()} />;
  if (roles.isError) return <Failure error={roles.error} onRetry={() => void roles.refetch()} />;

  const byName = new Map(roles.data.map((role) => [role.name, role]));
  const title = (name: string) => text(byName.get(name)?.title) ?? name;
  const assignable = roles.data.filter((role) => role.heldBy === undefined);
  const role: Role | undefined = byName.get(roleName);
  const open = role?.open ?? [];
  const complete = role !== undefined && open.every((name) => picked[name] !== undefined);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!complete) return;
    const resources = Object.fromEntries(open.map((name) => [name, picked[name] as string]));
    const assignment: Assignment = open.length > 0 ? { role: role.name, resources } : { role: role.name };
    assign.mutate(
      { subject, assignment },
      {
        onSuccess: () => {
          setRoleName('');
          setPicked({});
          onChanged?.({ subject, assignment, change: AssignmentChangeKind.assigned });
        },
      },
    );
  };

  return (
    <div className={cx('authz-assignment-editor', className)} data-subject={subject}>
      <section className="authz-assignment-editor__held">
        <h3 className="authz-assignment-editor__heading" part={Part.heading}>
          {messages.held}
        </h3>
        {held.data.length === 0 ? (
          <p className="authz-empty" part={Part.empty}>
            {messages.nothingHeld}
          </p>
        ) : (
          <ul className="authz-assignment-editor__list" part={Part.list}>
            {held.data.map((entry) => {
              const key = heldKey(entry);
              const removing =
                unassign.isPending &&
                unassign.variables !== undefined &&
                heldKey(unassign.variables.assignment) === key;
              return (
                <li
                  key={key}
                  className={cx('authz-held', `authz-held--${entry.through}`)}
                  part={Part.row}
                  data-role={entry.role}
                >
                  <span className="authz-held__role">{title(entry.role)}</span>
                  {Object.entries(entry.resources).map(([name, id]) => (
                    <span key={name} className="authz-held__resource" data-resource-name={name}>
                      <span className="authz-held__resource-name">{label(name)}</span>
                      <span className="authz-held__resource-id">{id}</span>
                    </span>
                  ))}
                  {entry.through === Through.authenticated ? (
                    <span className="authz-held__through">{messages.through}</span>
                  ) : (
                    canUnassign && (
                      <button
                        type="button"
                        className="authz-button authz-held__remove"
                        part={Part.button}
                        disabled={removing}
                        onClick={() => {
                          const assignment = { role: entry.role, resources: entry.resources };
                          unassign.mutate(
                            { subject, assignment },
                            {
                              onSuccess: () =>
                                onChanged?.({ subject, assignment, change: AssignmentChangeKind.unassigned }),
                            },
                          );
                        }}
                      >
                        {messages.unassign}
                      </button>
                    )
                  )}
                </li>
              );
            })}
          </ul>
        )}
        {unassign.isError && <Failure error={unassign.error} />}
      </section>

      {canAssign && (
        <form className="authz-assignment-editor__assign" part={Part.form} onSubmit={submit}>
          <label className="authz-field__label" part={Part.label} htmlFor={roleSelect}>
            {messages.role}
          </label>
          <select
            id={roleSelect}
            className="authz-select"
            part={Part.input}
            value={roleName}
            onChange={(event) => {
              setRoleName(event.target.value);
              setPicked({});
              assign.reset();
            }}
          >
            <option value="">{messages.chooseRole}</option>
            {assignable.map((candidate) => (
              <option key={candidate.name} value={candidate.name}>
                {text(candidate.title) ?? candidate.name}
              </option>
            ))}
          </select>
          {open.map((name) => (
            <ResourcePicker
              key={name}
              resourceName={name}
              language={language}
              value={picked[name] === undefined ? [] : [picked[name] as string]}
              onChange={(ids) =>
                setPicked((current) => {
                  const next = { ...current };
                  if (ids[0] === undefined) delete next[name];
                  else next[name] = ids[0];
                  return next;
                })
              }
            />
          ))}
          <button
            type="submit"
            className="authz-button authz-button--primary"
            part={parts(Part.button, Part.primary)}
            disabled={!complete || assign.isPending}
          >
            {messages.assign}
          </button>
          {assign.isError && <Failure error={assign.error} />}
        </form>
      )}
    </div>
  );
}
