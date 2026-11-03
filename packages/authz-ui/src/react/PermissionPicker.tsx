import { type KeyboardEvent, useId, useMemo, useState } from 'react';

import type { CatalogPermission, ServiceCatalog } from '../client';
import { Part } from '../styling';
import { useAuthz } from './context';
import { cx } from './parts';

export interface PermissionPickerProps {
  /** The permissions on offer, grouped by the service offering them. */
  offered: Array<{ service: ServiceCatalog; permissions: CatalogPermission[] }>;
  onPick(permission: string): void;
}

const matches = (query: string, service: ServiceCatalog, permission: CatalogPermission): boolean =>
  query === '' ||
  `${permission.summary ?? ''} ${permission.id} ${service.title} ${service.service}`.toLowerCase().includes(query);

/** Finds a permission to grant by its summary, id or service, the whole catalog a scroll away. */
export function PermissionPicker({ offered, onPick }: PermissionPickerProps) {
  const { messages } = useAuthz();
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const ids = useId();

  const groups = useMemo(() => {
    const wanted = query.trim().toLowerCase();
    return offered
      .map(({ service, permissions }) => ({
        service,
        permissions: permissions.filter((permission) => matches(wanted, service, permission)),
      }))
      .filter(({ permissions }) => permissions.length > 0);
  }, [offered, query]);
  const flat = groups.flatMap(({ permissions }) => permissions);
  const current = Math.min(active, Math.max(flat.length - 1, 0));

  const pick = (permission: string) => {
    onPick(permission);
    setQuery('');
    setActive(0);
    setOpen(false);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      setOpen(true);
      if (flat.length > 0) setActive((current + (event.key === 'ArrowDown' ? 1 : flat.length - 1)) % flat.length);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const chosen = open ? flat[current] : undefined;
      if (chosen !== undefined) pick(chosen.id);
    } else if (event.key === 'Escape') {
      setOpen(false);
    }
  };

  const optionId = (permission: string) => `${ids}-option-${permission}`;

  return (
    <div className="authz-permission-picker">
      <label className="authz-visually-hidden" htmlFor={`${ids}-input`}>
        {messages.addPermission}
      </label>
      <svg className="authz-permission-picker__icon" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
        <circle cx="7" cy="7" r="5" fill="none" stroke="currentColor" strokeWidth="1.6" />
        <path d="M11 11l3.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      </svg>
      <input
        id={`${ids}-input`}
        className="authz-input authz-permission-picker__input"
        part={Part.input}
        role="combobox"
        autoComplete="off"
        placeholder={`${messages.addPermission}…`}
        aria-expanded={open}
        aria-controls={`${ids}-list`}
        aria-activedescendant={open && flat[current] !== undefined ? optionId(flat[current].id) : undefined}
        value={query}
        onFocus={() => setOpen(true)}
        onClick={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onChange={(event) => {
          setQuery(event.target.value);
          setActive(0);
          setOpen(true);
        }}
        onKeyDown={onKeyDown}
      />
      {open && (
        <div id={`${ids}-list`} className="authz-permission-picker__menu" role="listbox" aria-label={messages.addPermission}>
          {groups.length === 0 && <p className="authz-permission-picker__none">{messages.noPermissionMatches}</p>}
          {groups.map(({ service, permissions }) => (
            <div key={service.service} role="group" aria-label={service.title} className="authz-permission-picker__group">
              <div className="authz-permission-picker__group-title" aria-hidden="true">
                {service.title} <code className="authz-permission-picker__prefix">{service.service}</code>
              </div>
              {permissions.map((permission) => (
                <div
                  key={permission.id}
                  id={optionId(permission.id)}
                  role="option"
                  aria-selected={flat[current]?.id === permission.id}
                  className={cx(
                    'authz-permission-picker__option',
                    flat[current]?.id === permission.id && 'authz-permission-picker__option--active',
                  )}
                  onMouseDown={(event) => event.preventDefault()}
                  onMouseEnter={() => setActive(flat.indexOf(permission))}
                  onClick={() => pick(permission.id)}
                >
                  <span className="authz-permission-picker__summary">{permission.summary ?? permission.id}</span>
                  <code className="authz-permission-picker__id">{permission.id}</code>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
