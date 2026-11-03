import type { ReactNode } from 'react';

import { HeldBy, Owner, type Role, type Verdict, VerdictReason } from '../client';
import { Part } from '../styling';
import { useAuthz } from './context';
import { useLiveComposition, useRoles } from './hooks';
import type { Messages } from './messages';
import { cx, Failure, Loading, useText } from './parts';

const verdictLabel = {
  [VerdictReason.accepted]: 'verdictAccepted',
  [VerdictReason.refused]: 'verdictRefused',
  [VerdictReason.waiting]: 'verdictWaiting',
} as const satisfies Record<Verdict['reason'], keyof Messages>;

export function VerdictBadge({ verdict }: { verdict: Verdict | undefined }) {
  const { messages } = useAuthz();
  const reason = verdict?.reason;
  const label = reason === undefined ? messages.verdictUnread : messages[verdictLabel[reason]];
  return (
    <span
      className={cx('authz-verdict', `authz-verdict--${reason?.toLowerCase() ?? 'unread'}`)}
      part={Part.verdict}
    >
      <span className="authz-verdict__reason">{label}</span>
      {verdict?.message !== undefined && <span className="authz-verdict__message">{verdict.message}</span>}
    </span>
  );
}

export interface RoleListProps {
  language?: string;
  /** The role shown as selected. */
  selected?: string;
  onSelect?(role: Role): void;
  /** What an app offers beside each role, such as edit or delete. */
  actions?(role: Role): ReactNode;
  className?: string;
}

/**
 * Every role, the ones every signed-in subject holds in their own section,
 * each verdict current as the IAM reaches it.
 */
export function RoleList({ language, selected, onSelect, actions, className }: RoleListProps) {
  const { messages } = useAuthz();
  const text = useText(language);
  useLiveComposition();
  const roles = useRoles();

  if (roles.isPending) return <Loading />;
  if (roles.isError) return <Failure error={roles.error} onRetry={() => void roles.refetch()} />;

  const item = (role: Role) => {
    const title = text(role.title) ?? role.name;
    const description = text(role.description);
    return (
      <li
        key={role.name}
        className={cx('authz-role', role.name === selected && 'authz-role--selected')}
        part={Part.row}
        data-role={role.name}
      >
        <div className="authz-role__head">
          {onSelect !== undefined ? (
            <button
              type="button"
              className="authz-role__title"
              aria-pressed={role.name === selected}
              onClick={() => onSelect(role)}
            >
              {title}
            </button>
          ) : (
            <span className="authz-role__title">{title}</span>
          )}
          {title !== role.name && <code className="authz-role__name">{role.name}</code>}
        </div>
        {description !== undefined && <p className="authz-role__description">{description}</p>}
        <div className="authz-role__status">
          <span className={cx('authz-role__owner', `authz-role__owner--${role.owner}`)}>
            {role.owner === Owner.iam ? messages.ownerIam : messages.ownerDeployment}
          </span>
          <VerdictBadge verdict={role.ready} />
        </div>
        {actions !== undefined && (
          <div className="authz-role__actions" part={Part.actions}>
            {actions(role)}
          </div>
        )}
      </li>
    );
  };

  const everyone = roles.data.filter((role) => role.heldBy === HeldBy.authenticated);
  const assignable = roles.data.filter((role) => role.heldBy === undefined);

  return (
    <div className={cx('authz-role-list', className)}>
      {everyone.length > 0 && (
        <section className="authz-role-list__section authz-role-list__section--everyone">
          <h3 className="authz-role-list__heading" part={Part.heading}>
            {messages.rolesHeldByEveryone}
          </h3>
          <ul className="authz-role-list__roles" part={Part.list}>
            {everyone.map(item)}
          </ul>
        </section>
      )}
      <section className="authz-role-list__section authz-role-list__section--assignable">
        <h3 className="authz-role-list__heading" part={Part.heading}>
          {messages.roles}
        </h3>
        {assignable.length === 0 ? (
          <p className="authz-empty" part={Part.empty}>
            {messages.noRoles}
          </p>
        ) : (
          <ul className="authz-role-list__roles" part={Part.list}>
            {assignable.map(item)}
          </ul>
        )}
      </section>
    </div>
  );
}
