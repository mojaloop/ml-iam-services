import { useState } from 'react';

import { type Subject, SubjectKind } from '../client';
import { Part } from '../styling';
import { useAuthz } from './context';
import { useSubjects } from './hooks';
import { cx, Failure, Loading, Pager } from './parts';

const PAGE_SIZE = 10;

export interface SubjectListProps {
  /** The subject shown as selected. */
  selected?: string;
  /** Offered on each subject; without it the list is read only. */
  onSelect?(subject: Subject): void;
  /** How many subjects a page shows. */
  pageSize?: number;
  className?: string;
}

/** The people and machine clients that can hold roles, a page at a time. */
export function SubjectList({ selected, onSelect, pageSize = PAGE_SIZE, className }: SubjectListProps) {
  const { messages } = useAuthz();
  const subjects = useSubjects();
  const [page, setPage] = useState(0);

  if (subjects.isPending) return <Loading />;
  if (subjects.isError) return <Failure error={subjects.error} onRetry={() => void subjects.refetch()} />;
  if (subjects.data.length === 0) {
    return (
      <p className={cx('authz-empty', className)} part={Part.empty}>
        {messages.noSubjects}
      </p>
    );
  }

  const size = Number.isInteger(pageSize) && pageSize > 0 ? pageSize : PAGE_SIZE;
  const pages = Math.ceil(subjects.data.length / size);
  const shown = Math.min(page, pages - 1);
  const rows = subjects.data.slice(shown * size, (shown + 1) * size);

  return (
    <div className={cx('authz-subject-list', className)}>
      <table className="authz-subject-list__table" part={Part.table}>
        <thead>
          <tr>
            {[messages.name, messages.email, messages.kind].map((heading) => (
              <th key={heading} scope="col" className="authz-subject-list__heading" part={Part.heading}>
                {heading}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((subject) => {
            const name = subject.name ?? subject.id;
            return (
              <tr
                key={subject.id}
                className={cx('authz-subject', subject.id === selected && 'authz-subject--selected')}
                part={Part.row}
                data-subject={subject.id}
              >
                <td className="authz-subject__name" part={Part.cell}>
                  {onSelect !== undefined ? (
                    <button
                      type="button"
                      className="authz-subject__open"
                      part={Part.button}
                      aria-pressed={subject.id === selected}
                      onClick={() => onSelect(subject)}
                    >
                      {name}
                    </button>
                  ) : (
                    name
                  )}
                </td>
                <td className="authz-subject__email" part={Part.cell}>
                  {subject.email}
                </td>
                <td className="authz-subject__kind" part={Part.cell}>
                  {subject.kind === SubjectKind.person ? messages.person : messages.client}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {pages > 1 && <Pager page={shown} pages={pages} onPage={setPage} />}
    </div>
  );
}
