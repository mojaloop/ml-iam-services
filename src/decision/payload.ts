/**
 * The rendered payload arriving from a gateway rule. The vocabulary is closed:
 * a payload carrying anything else is a denial.
 */

export interface Check {
  namespace: string;
  object: string;
  relation: string;
  subject_id: string;
}

/**
 * One declared scope: the resource name is what the grants hold, the type is
 * what the caller's service reads back in X-Scope.
 */
export interface ScopePair {
  type: string;
  resourceName: string;
  /** Brought in by `$resources`: holding none of it reaches none, rather than refusing the request. */
  followsAssignment?: true;
}

export interface Payload {
  checks: Check[];
  /** The scopes the operation declared, asked for in X-Scope. */
  scope: ScopePair[];
}

const CHECK_KEYS = ['namespace', 'object', 'relation', 'subject_id'];
const SCOPE_KEYS = ['type', 'resourceName'];
const FOLLOWS = 'followsAssignment';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const text = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

const asCheck = (value: unknown): Check | undefined => {
  if (!isRecord(value)) return undefined;
  if (Object.keys(value).some((key) => !CHECK_KEYS.includes(key))) return undefined;
  if (!CHECK_KEYS.every((key) => text(value[key]))) return undefined;
  return value as unknown as Check;
};

const asScopePair = (value: unknown): ScopePair | undefined => {
  if (!isRecord(value)) return undefined;
  if (Object.keys(value).some((key) => !SCOPE_KEYS.includes(key) && key !== FOLLOWS)) return undefined;
  if (!SCOPE_KEYS.every((key) => text(value[key]))) return undefined;
  if (value[FOLLOWS] !== undefined && value[FOLLOWS] !== true) return undefined;
  return value as unknown as ScopePair;
};

export function parsePayload(raw: unknown): Payload | undefined {
  if (!isRecord(raw)) return undefined;

  const { scope: rawScope, ...rest } = raw;
  if (rawScope !== undefined && !Array.isArray(rawScope)) return undefined;
  const pairs = ((rawScope ?? []) as unknown[]).map(asScopePair);
  if (pairs.some((p) => p === undefined)) return undefined;
  const scope = pairs as ScopePair[];
  if (new Set(scope.map((p) => p.type)).size !== scope.length) return undefined;

  if ('allOf' in rest) {
    const { allOf, ...extra } = rest;
    if (Object.keys(extra).length > 0) return undefined;
    if (!Array.isArray(allOf) || allOf.length === 0) return undefined;
    const checks = allOf.map(asCheck);
    if (checks.some((c) => c === undefined)) return undefined;
    return { checks: checks as Check[], scope };
  }

  const check = asCheck(rest);
  if (check === undefined) return undefined;
  return { checks: [check], scope };
}
