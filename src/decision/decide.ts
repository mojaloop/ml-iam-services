import { Scope, ScopeEntry } from '@mojaloop/authz/gateway';

import type { KetoReader } from '../iam/keto';
import { AUTHENTICATED, HELD_BY, MEMBERS, ROLE_NAMESPACE, SubjectSet, Tuple, TYPE_WIDE } from '../iam/materialize';
import { parseResource, resourceObject } from '../iam/registry';
import { Check, Payload } from './payload';

/** What a service sees when the request carried no row filtering. */
export const NO_SCOPE: Scope = new Map();

export interface Decision {
  allowed: boolean;
  scope: Scope;
  violations: Tuple[];
}

/**
 * A grant on the type-wide object covers every resource of that type, present
 * and future, so it answers the same question as a grant on the resource
 * itself. The singleton has no wider form.
 */
const objectsFor = (object: string): string[] => {
  const resource = parseResource(object);
  return resource === undefined ? [object] : [object, resourceObject(resource.resourceName, TYPE_WIDE)];
};

const members = (role: string): SubjectSet => ({ namespace: ROLE_NAMESPACE, object: role, relation: MEMBERS });

/** The roles every authenticated subject holds, which no membership records. */
export const heldByEveryone = async (keto: KetoReader): Promise<string[]> =>
  (await keto.query({ namespace: ROLE_NAMESPACE, relation: HELD_BY, subject_id: AUTHENTICATED })).map((t) => t.object);

const passes = async (keto: KetoReader, c: Check, everyone: string[]): Promise<boolean> => {
  for (const object of objectsFor(c.object)) {
    if (await keto.check(c.namespace, object, c.relation, c.subject_id)) return true;
    for (const role of everyone) {
      if (await keto.check(c.namespace, object, c.relation, members(role))) return true;
    }
  }
  return false;
};

/** One role's grants, or the grants written straight to the caller. */
interface Holder {
  tuples: Tuple[];
  direct: boolean;
}

/**
 * Every grant the caller holds in one service namespace, reached the way
 * evaluation reaches it: through the caller's roles. Keto has no subject-first
 * index, so this walks. Evaluation honours a grant written straight to the
 * user, so the walk mirrors that path and reports one where it finds it.
 *
 * The grants stay grouped by what carries them, because a role is a statement
 * about one operation over one set of resources, and merging two roles would
 * invent combinations neither of them granted.
 */
export async function grantHolders(
  keto: KetoReader,
  namespace: string,
  subjectId: string,
  everyone: string[],
): Promise<Holder[]> {
  const roles = await keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS, subject_id: subjectId });
  const instances = [...new Set([...roles.map((role) => role.object), ...everyone])];
  const held = await Promise.all(
    instances.map((role) =>
      keto.query({
        namespace,
        'subject_set.namespace': ROLE_NAMESPACE,
        'subject_set.object': role,
        'subject_set.relation': MEMBERS,
      }),
    ),
  );
  const direct = await keto.query({ namespace, subject_id: subjectId });
  const holders = held.map((tuples) => ({ tuples, direct: false }));
  return direct.length === 0 ? holders : [...holders, { tuples: direct, direct: true }];
}

/** Whether one holder carries every check the request had to pass. */
const admits = (holder: Holder, checks: Check[]): boolean =>
  checks.every((c) =>
    holder.tuples.some((t) => t.relation === c.relation && objectsFor(c.object).includes(t.object)),
  );

/**
 * The resources of one type the caller may see, defined as holding any grant
 * on the resource. That is exactly what this finds, so the header and a
 * per-resource check can never disagree.
 */
const overType = (tuples: Tuple[], resourceName: string): ScopeEntry => {
  const ids = new Set<string>();
  let all = false;
  for (const tuple of tuples) {
    const resource = parseResource(tuple.object);
    if (resource?.resourceName !== resourceName) continue;
    if (resource.id === TYPE_WIDE) all = true;
    else ids.add(resource.id);
  }
  return { all, ids: [...ids].sort() };
};

/**
 * Verdicts come only from Keto evaluating stored grants; this composes them.
 * Every allow carries a scope, so a service can tell an authorized request
 * from one that never passed through the gateway.
 */
export async function decide(payload: Payload, keto: KetoReader): Promise<Decision> {
  const namespace = payload.checks[0]!.namespace;
  if (payload.checks.some((c) => c.namespace !== namespace)) {
    return { allowed: false, scope: NO_SCOPE, violations: [] };
  }

  const everyone = await heldByEveryone(keto);
  for (const c of payload.checks) {
    if (!(await passes(keto, c, everyone))) return { allowed: false, scope: NO_SCOPE, violations: [] };
  }

  if (payload.scope.length === 0) {
    return { allowed: true, scope: NO_SCOPE, violations: [] };
  }

  const holders = await grantHolders(keto, namespace, payload.checks[0]!.subject_id, everyone);
  const violations = holders.filter((h) => h.direct).flatMap((h) => h.tuples);
  // Only the grant that admitted this request says what it may see: a role's
  // grant of another operation lends this one none of its resources.
  const relations = new Set(payload.checks.map((c) => c.relation));
  const tuples = holders
    .filter((h) => admits(h, payload.checks))
    .flatMap((h) => h.tuples.filter((t) => relations.has(t.relation)));
  const visible: Scope = new Map();
  for (const pair of payload.scope) {
    // The grants hold the resource name; the caller's service reads its own
    // spelling back in X-Scope.
    const seen = overType(tuples, pair.resourceName);
    // A declared scope the caller has no standing in is a denial. An empty
    // list would read as "no restriction" in a query layer and return the
    // whole table, and on a write it would leave the caller unattributable.
    // A name `$resources` brought in is the operation's reach over it, which
    // may be none, and the service asks its guard for exactly that.
    if (!seen.all && seen.ids.length === 0 && pair.followsAssignment !== true) {
      return { allowed: false, scope: NO_SCOPE, violations };
    }
    visible.set(pair.type, seen);
  }
  return { allowed: true, scope: visible, violations };
}
