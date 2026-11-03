import { type FormEvent, useId, useMemo, useState } from 'react';

import { indexCatalog, scopingResourceNames } from '../catalog';
import type { RoleSave } from '../changes';
import { ALL, type Grant, type Localized, Owner, type ResourceSet, type Role, type RoleSpec } from '../client';
import { Part, parts } from '../styling';
import { useAuthz, useLanguage } from './context';
import { useCatalog, useCreateRole, useDeleteRole, useLiveComposition, useResourceNames, useUpdateRole } from './hooks';
import { cx, Failure, Loading, useResourceNameLabel, useText } from './parts';
import { ResourcePicker } from './ResourcePicker';

/** What a grant says of one resource name: left to the assignment, every one, or the ones it names. */
const Mode = { open: 'open', all: 'all', some: 'some' } as const;
type Mode = (typeof Mode)[keyof typeof Mode];

type Scope = { mode: typeof Mode.all } | { mode: typeof Mode.some; ids: string[] };

interface GrantDraft {
  permission: string;
  /** Per resource name the grant names; a resource name left out is the assignment's to name. */
  scopes: Record<string, Scope>;
}

interface Draft {
  name: string;
  title?: Localized;
  description?: Localized;
  grants: GrantDraft[];
}

const NAME = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const NAME_MAX = 63;

const toScope = (set: ResourceSet): Scope =>
  set === ALL ? { mode: Mode.all } : { mode: Mode.some, ids: Array.isArray(set) ? set : [set] };

const fromRole = (role: Role | undefined): Draft => ({
  name: role?.name ?? '',
  title: role?.title,
  description: role?.description,
  grants: (role?.grants ?? []).map((grant) => ({
    permission: grant.permission,
    scopes: Object.fromEntries(Object.entries(grant.resources ?? {}).map(([name, set]) => [name, toScope(set)])),
  })),
});

const toGrant = ({ permission, scopes }: GrantDraft): Grant => {
  const resources: Record<string, ResourceSet> = {};
  for (const [name, scope] of Object.entries(scopes)) resources[name] = scope.mode === Mode.all ? ALL : scope.ids;
  return Object.keys(resources).length > 0 ? { permission, resources } : { permission };
};

/** The entry the editor shows is the one an edit changes: the language's, else the first. */
function withText(value: Localized | undefined, text: string, language: string | undefined): Localized {
  if (value === undefined || typeof value === 'string') return text;
  const key = language !== undefined && language in value ? language : (Object.keys(value)[0] ?? language);
  return key === undefined ? text : { ...value, [key]: text };
}

/** What is sent: the entries that say something, or nothing. */
function settled(value: Localized | undefined): Localized | undefined {
  if (value === undefined || typeof value === 'string') return value === '' ? undefined : value;
  const entries = Object.entries(value).filter(([, text]) => text !== '');
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

export interface RoleEditorProps {
  /** The role to change; absent composes a new one. */
  role?: Role;
  /** The caller may not write roles: the role is shown, not edited. */
  readOnly?: boolean;
  /** Offer deleting the role. */
  allowDelete?: boolean;
  language?: string;
  /** Asked before the role is sent; `false` keeps it unsent, as the user left it. */
  beforeSave?(save: RoleSave): boolean | void;
  onSaved?(role: Role): void;
  onDeleted?(role: string): void;
  onCancel?(): void;
  className?: string;
}

/**
 * Composes a role from the catalog's permissions, or changes one the IAM owns.
 * A role the deployment applied is shown read-only, since it changes where the
 * deployment keeps it.
 */
export function RoleEditor({
  role,
  readOnly = false,
  allowDelete = false,
  language,
  beforeSave,
  onSaved,
  onDeleted,
  onCancel,
  className,
}: RoleEditorProps) {
  const { messages } = useAuthz();
  const resolvedLanguage = useLanguage(language);
  const text = useText(language);
  const label = useResourceNameLabel(language);
  useLiveComposition();
  const catalog = useCatalog();
  const resourceNames = useResourceNames();
  const create = useCreateRole();
  const update = useUpdateRole();
  const remove = useDeleteRole();
  const [source, setSource] = useState(role?.name);
  const [draft, setDraft] = useState<Draft>(() => fromRole(role));
  const [adding, setAdding] = useState('');
  const [confirming, setConfirming] = useState(false);
  const ids = useId();

  if (role?.name !== source) {
    setSource(role?.name);
    setDraft(fromRole(role));
    setConfirming(false);
  }

  const index = useMemo(() => indexCatalog(catalog.data ?? []), [catalog.data]);

  if (catalog.isPending || resourceNames.isPending) return <Loading />;
  if (catalog.isError) return <Failure error={catalog.error} onRetry={() => void catalog.refetch()} />;
  if (resourceNames.isError) return <Failure error={resourceNames.error} onRetry={() => void resourceNames.refetch()} />;

  /** A role names ids only of the IAM's own resource names; every other one it fixes to all or leaves open. */
  const nameable = (name: string): boolean => resourceNames.data?.[name]?.own === true;

  const isNew = role === undefined;
  const ownedElsewhere = role?.owner === Owner.deployment;
  const locked = readOnly || ownedElsewhere;
  const saving = create.isPending || update.isPending;

  const problems: string[] = [];
  if (isNew && (!NAME.test(draft.name) || draft.name.length > NAME_MAX)) problems.push(messages.namePattern);
  if (draft.grants.length === 0) problems.push(messages.noGrants);
  for (const grant of draft.grants) {
    for (const [name, scope] of Object.entries(grant.scopes)) {
      if (scope.mode === Mode.some && scope.ids.length === 0) {
        problems.push(`${grant.permission}: ${label(name)}: ${messages.chooseResource}`);
      }
    }
  }

  const setGrant = (at: number, change: (grant: GrantDraft) => GrantDraft) =>
    setDraft((current) => ({
      ...current,
      grants: current.grants.map((grant, i) => (i === at ? change(grant) : grant)),
    }));

  const setScope = (at: number, name: string, scope: Scope | undefined) =>
    setGrant(at, (grant) => {
      const scopes = { ...grant.scopes };
      if (scope === undefined) delete scopes[name];
      else scopes[name] = scope;
      return { ...grant, scopes };
    });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (locked || problems.length > 0) return;
    const title = settled(draft.title);
    const description = settled(draft.description);
    const spec: RoleSpec = {
      ...(title !== undefined ? { title } : {}),
      ...(description !== undefined ? { description } : {}),
      grants: draft.grants.map(toGrant),
    };
    if (beforeSave?.({ name: isNew ? draft.name : role.name, spec, create: isNew }) === false) return;
    if (isNew) create.mutate({ name: draft.name, ...spec }, { onSuccess: (saved) => onSaved?.(saved) });
    else update.mutate({ role: role.name, spec }, { onSuccess: (saved) => onSaved?.(saved) });
  };

  const granted = new Set(draft.grants.map((grant) => grant.permission));
  const offered = (catalog.data ?? [])
    .map((service) => ({ service, permissions: service.permissions.filter((p) => !p.deprecated && !granted.has(p.id)) }))
    .filter(({ permissions }) => permissions.length > 0);

  const describeScope = (scope: Scope | undefined) =>
    scope === undefined ? messages.scopeOpen : scope.mode === Mode.all ? messages.scopeAll : scope.ids.join(', ');

  const failure = create.error ?? update.error ?? remove.error;

  return (
    <form
      className={cx('authz-role-editor', locked && 'authz-role-editor--read-only', className)}
      part={Part.form}
      data-role={role?.name}
      onSubmit={submit}
    >
      {ownedElsewhere && <p className="authz-role-editor__notice">{messages.readOnlyDeployment}</p>}

      <div className="authz-field" part={Part.field}>
        <label className="authz-field__label" part={Part.label} htmlFor={`${ids}-name`}>
          {messages.name}
        </label>
        {isNew && !locked ? (
          <input
            id={`${ids}-name`}
            className="authz-input"
            part={Part.input}
            value={draft.name}
            maxLength={NAME_MAX}
            required
            aria-describedby={`${ids}-name-hint`}
            onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))}
          />
        ) : (
          <code id={`${ids}-name`} className="authz-field__value">
            {draft.name}
          </code>
        )}
        {isNew && !locked && (
          <span id={`${ids}-name-hint`} className="authz-field__hint">
            {messages.namePattern}
          </span>
        )}
      </div>

      {(['title', 'description'] as const).map((field) => (
        <div key={field} className="authz-field" part={Part.field}>
          <label className="authz-field__label" part={Part.label} htmlFor={`${ids}-${field}`}>
            {messages[field]}
          </label>
          {locked ? (
            <span id={`${ids}-${field}`} className="authz-field__value">
              {text(draft[field])}
            </span>
          ) : (
            <input
              id={`${ids}-${field}`}
              className="authz-input"
              part={Part.input}
              value={text(draft[field]) ?? ''}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  [field]: withText(current[field], event.target.value, resolvedLanguage),
                }))
              }
            />
          )}
        </div>
      ))}

      <section className="authz-role-editor__grants">
        <h3 className="authz-role-editor__heading" part={Part.heading}>
          {messages.grants}
        </h3>
        <ul className="authz-role-editor__grant-list" part={Part.list}>
          {draft.grants.map((grant, at) => {
            const offeredBy = index.get(grant.permission);
            const names = [
              ...(offeredBy !== undefined ? scopingResourceNames(offeredBy.permission) : []),
              ...Object.keys(grant.scopes),
            ].filter((name, i, all) => all.indexOf(name) === i);
            return (
              <li key={grant.permission} className="authz-grant" part={Part.grant} data-permission={grant.permission}>
                <div className="authz-grant__head">
                  <span className="authz-grant__label">{offeredBy?.permission.summary ?? grant.permission}</span>
                  {offeredBy !== undefined && <span className="authz-grant__service">{offeredBy.service.title}</span>}
                  <code className="authz-grant__id">{grant.permission}</code>
                  {offeredBy?.permission.deprecated === true && (
                    <span className="authz-grant__deprecated">{messages.deprecated}</span>
                  )}
                  {offeredBy === undefined && <span className="authz-grant__unknown">{messages.unknownPermission}</span>}
                  {!locked && (
                    <button
                      type="button"
                      className="authz-button authz-grant__remove"
                      part={Part.button}
                      onClick={() =>
                        setDraft((current) => ({ ...current, grants: current.grants.filter((_, i) => i !== at) }))
                      }
                    >
                      {messages.removeGrant}
                    </button>
                  )}
                </div>
                {names.map((name) => {
                  const scope = grant.scopes[name];
                  const mode: Mode = scope?.mode ?? Mode.open;
                  const modes: Array<[Mode, string]> = [
                    [Mode.open, messages.scopeOpen],
                    [Mode.all, messages.scopeAll],
                    ...(nameable(name) ? [[Mode.some, messages.scopeSome] as [Mode, string]] : []),
                  ];
                  const group = `${ids}-${at}-${name}`;
                  if (locked) {
                    return (
                      <div key={name} className="authz-scope" part={Part.scope} data-resource-name={name}>
                        <span className="authz-scope__name">{label(name)}</span>
                        <span className="authz-scope__value">{describeScope(scope)}</span>
                      </div>
                    );
                  }
                  return (
                    <fieldset key={name} className="authz-scope" part={Part.scope} data-resource-name={name}>
                      <legend className="authz-scope__name">{label(name)}</legend>
                      {modes.map(([value, caption]) => (
                        <label key={value} className="authz-scope__option">
                          <input
                            type="radio"
                            name={group}
                            value={value}
                            checked={mode === value}
                            onChange={() =>
                              setScope(
                                at,
                                name,
                                value === Mode.open
                                  ? undefined
                                  : value === Mode.all
                                    ? { mode: Mode.all }
                                    : { mode: Mode.some, ids: scope?.mode === Mode.some ? scope.ids : [] },
                              )
                            }
                          />
                          {caption}
                        </label>
                      ))}
                      {scope?.mode === Mode.some && (
                        <ResourcePicker
                          multiple
                          resourceName={name}
                          language={language}
                          value={scope.ids}
                          onChange={(chosen) => setScope(at, name, { mode: Mode.some, ids: chosen })}
                        />
                      )}
                    </fieldset>
                  );
                })}
              </li>
            );
          })}
        </ul>

        {!locked && (
          <div className="authz-role-editor__add" part={Part.field}>
            <label className="authz-field__label" part={Part.label} htmlFor={`${ids}-add`}>
              {messages.permission}
            </label>
            <select
              id={`${ids}-add`}
              className="authz-select"
              part={Part.input}
              value={adding}
              onChange={(event) => setAdding(event.target.value)}
            >
              <option value="" />
              {offered.map(({ service, permissions }) => (
                <optgroup key={service.service} label={service.title}>
                  {permissions.map((permission) => (
                    <option key={permission.id} value={permission.id}>
                      {permission.summary ?? permission.id}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
            <button
              type="button"
              className="authz-button"
              part={Part.button}
              disabled={adding === ''}
              onClick={() => {
                setDraft((current) => ({ ...current, grants: [...current.grants, { permission: adding, scopes: {} }] }));
                setAdding('');
              }}
            >
              {messages.addGrant}
            </button>
          </div>
        )}
      </section>

      {!locked && problems.length > 0 && (
        <ul className="authz-role-editor__problems" part={Part.problems}>
          {problems.map((problem, at) => (
            <li key={at}>{problem}</li>
          ))}
        </ul>
      )}
      {failure !== null && <Failure error={failure} />}

      <div className="authz-role-editor__actions" part={Part.actions}>
        {!locked && (
          <button
            type="submit"
            className="authz-button authz-button--primary"
            part={parts(Part.button, Part.primary)}
            disabled={problems.length > 0 || saving}
          >
            {isNew ? messages.create : messages.save}
          </button>
        )}
        {onCancel !== undefined && (
          <button type="button" className="authz-button" part={Part.button} onClick={onCancel}>
            {messages.cancel}
          </button>
        )}
        {allowDelete && !locked && !isNew && (
          confirming ? (
            <button
              type="button"
              className="authz-button authz-button--danger"
              part={parts(Part.button, Part.danger)}
              disabled={remove.isPending}
              onClick={() => remove.mutate(role.name, { onSuccess: () => onDeleted?.(role.name) })}
            >
              {messages.confirmDelete}
            </button>
          ) : (
            <button
              type="button"
              className="authz-button authz-button--danger"
              part={parts(Part.button, Part.danger)}
              onClick={() => setConfirming(true)}
            >
              {messages.deleteRole}
            </button>
          )
        )}
      </div>
    </form>
  );
}
