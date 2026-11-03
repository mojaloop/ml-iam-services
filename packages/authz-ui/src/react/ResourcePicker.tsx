import { useId } from 'react';

import { Part } from '../styling';
import { useAuthz } from './context';
import { useResources } from './hooks';
import { cx, Failure, Loading, useResourceNameLabel } from './parts';

export interface ResourcePickerProps {
  resourceName: string;
  /** The chosen ids; one at most unless `multiple`. */
  value: string[];
  onChange(ids: string[]): void;
  multiple?: boolean;
  disabled?: boolean;
  language?: string;
  className?: string;
}

/** Chooses among the resources that exist of one resource name. */
export function ResourcePicker({
  resourceName,
  value,
  onChange,
  multiple = false,
  disabled = false,
  language,
  className,
}: ResourcePickerProps) {
  const { messages } = useAuthz();
  const label = useResourceNameLabel(language);
  const resources = useResources(resourceName);
  const id = useId();

  if (resources.isPending) return <Loading />;
  if (resources.isError) return <Failure error={resources.error} onRetry={() => void resources.refetch()} />;

  const ids = resources.data.resources.map((resource) => resource.id);
  const classes = cx('authz-resource-picker', multiple && 'authz-resource-picker--multiple', className);
  const stale = resources.data.stale.includes(resourceName) && (
    <p className="authz-resource-picker__stale" role="status">
      {messages.staleResources}
    </p>
  );

  if (ids.length === 0) {
    return (
      <div className={classes} data-resource-name={resourceName}>
        <span className="authz-resource-picker__label">{label(resourceName)}</span>
        <p className="authz-empty" part={Part.empty}>
          {messages.noResources}
        </p>
        {stale}
      </div>
    );
  }

  if (multiple) {
    return (
      <fieldset className={classes} data-resource-name={resourceName} disabled={disabled}>
        <legend className="authz-resource-picker__label">{label(resourceName)}</legend>
        <div className="authz-chips">
          {ids.map((resource) => (
            <label key={resource} className="authz-chip">
              <input
                type="checkbox"
                part={Part.input}
                checked={value.includes(resource)}
                onChange={(event) =>
                  onChange(
                    event.target.checked ? [...value, resource] : value.filter((chosen) => chosen !== resource),
                  )
                }
              />
              <span>{resource}</span>
            </label>
          ))}
        </div>
        {stale}
      </fieldset>
    );
  }

  return (
    <div className={classes} data-resource-name={resourceName}>
      <label className="authz-resource-picker__label" part={Part.label} htmlFor={id}>
        {label(resourceName)}
      </label>
      <select
        id={id}
        className="authz-select"
        part={Part.input}
        value={value[0] ?? ''}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value === '' ? [] : [event.target.value])}
      >
        <option value="">{messages.chooseResource}</option>
        {ids.map((resource) => (
          <option key={resource} value={resource}>
            {resource}
          </option>
        ))}
      </select>
      {stale}
    </div>
  );
}
