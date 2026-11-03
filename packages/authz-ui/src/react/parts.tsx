import { useCallback } from 'react';

import { AuthzError, type Localized, localize } from '../client';
import { Part } from '../styling';
import { useAuthz, useLanguage } from './context';
import { useResourceNames } from './hooks';

export const cx = (...names: Array<string | false | undefined>): string => names.filter(Boolean).join(' ');

/** Resolves display text in the component's language. */
export function useText(language?: string): (text: Localized | undefined) => string | undefined {
  const resolved = useLanguage(language);
  return useCallback((text: Localized | undefined) => localize(text, resolved), [resolved]);
}

/** A resource name's label, or the name itself while the IAM gives none. */
export function useResourceNameLabel(language?: string): (resourceName: string) => string {
  const text = useText(language);
  const { data } = useResourceNames();
  return useCallback(
    (resourceName: string) => text(data?.[resourceName]?.label) ?? resourceName,
    [data, text],
  );
}

export function Loading() {
  const { messages } = useAuthz();
  return (
    <p className="authz-loading" part={Part.loading} role="status">
      {messages.loading}
    </p>
  );
}

export interface FailureProps {
  error: Error;
  onRetry?: () => void;
}

/** The reasons a request was refused, one per line, as the IAM gave them. */
export function Failure({ error, onRetry }: FailureProps) {
  const { messages } = useAuthz();
  const reasons = error instanceof AuthzError && error.errors.length > 0 ? error.errors : [error.message];
  return (
    <div className="authz-failure" part={Part.failure} role="alert">
      <ul className="authz-failure__reasons">
        {reasons.map((reason) => (
          <li key={reason}>{reason}</li>
        ))}
      </ul>
      {onRetry !== undefined && (
        <button type="button" className="authz-button authz-failure__retry" part={Part.button} onClick={onRetry}>
          {messages.retry}
        </button>
      )}
    </div>
  );
}

export interface PagerProps {
  page: number;
  pages: number;
  onPage(page: number): void;
}

/** Moves through a list shown a page at a time; `page` counts from 0. */
export function Pager({ page, pages, onPage }: PagerProps) {
  const { messages } = useAuthz();
  return (
    <nav className="authz-pager" part={Part.pager}>
      <button
        type="button"
        className="authz-button"
        part={Part.button}
        disabled={page === 0}
        onClick={() => onPage(page - 1)}
      >
        {messages.previousPage}
      </button>
      <span className="authz-pager__status">{messages.page(page + 1, pages)}</span>
      <button
        type="button"
        className="authz-button"
        part={Part.button}
        disabled={page >= pages - 1}
        onClick={() => onPage(page + 1)}
      >
        {messages.nextPage}
      </button>
    </nav>
  );
}
