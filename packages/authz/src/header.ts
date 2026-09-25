/**
 * How the platform carries a decision from the endpoint that made it to the
 * service that answers under it.
 *
 * Private to this package. A service never sees any of it: it declares what
 * it guards and asks whether a request is allowed, and nothing in its code
 * says what a scope is or where it travels. Both directions live in one file
 * because a reader that parsed the format slightly differently from the
 * writer would be a silent data leak in that service rather than a parse
 * error.
 *
 *   orders=*                        every resource of that type
 *   orders=o7,o11                   those resources
 *   customers=acme;orders=o1        several types at once
 *   none                            no type is in play, nothing is visible
 */

/** What one decision says about one resource type. */
export interface ScopeEntry {
  /** Every id of the type, which renders as a wildcard. */
  all: boolean;
  /** The ids it names otherwise. */
  ids: string[];
}

/** A decision, by resource type. */
export type Scope = Map<string, ScopeEntry>;

/** Headers as a framework hands them over. */
export type RequestHeaders = Record<string, string | undefined> | Headers;

/** The header this contract travels in. */
export const HEADER = 'x-scope';

/** What the header says when the operation declared no resource type. */
export const NONE = 'none';

/**
 * A call with no gateway in the path: one service calling another, a
 * background job, a test. It is passed by name, so an unrestricted read is
 * always something someone wrote rather than something that happened when a
 * scope went missing.
 */
export const UNRESTRICTED: unique symbol = Symbol.for('@mojaloop/authz.INTERNAL');

/**
 * Renders a visible set per type. An entry marked `all` collapses to `*`;
 * everything else lists its ids.
 */
export const formatScope = (scope: Scope): string => {
  const parts: string[] = [];
  for (const [type, visible] of scope) {
    parts.push(`${type}=${visible.all ? '*' : visible.ids.join(',')}`);
  }
  return parts.length === 0 ? NONE : parts.join(';');
};

/**
 * The headers an allow carries. Callers hand over a scope and never the name
 * it travels under, which is why a service cannot spell it one way while the
 * endpoint writing it spells it another.
 */
export const scopeHeaders = (scope: Scope): Record<string, string> => ({ [HEADER]: formatScope(scope) });

/**
 * Whatever a framework calls headers, read one by name. Anything carrying a
 * `get` is asked through it; anything else is indexed.
 */
const headerValue = (headers: RequestHeaders | undefined): string | null | undefined => {
  const get = (headers as Headers | undefined)?.get;
  if (typeof get === 'function') return (headers as Headers).get(HEADER);
  return (headers as Record<string, string | undefined> | undefined)?.[HEADER];
};

/**
 * Reads a request's scope. Anything unparseable yields no types, which shows
 * nothing, because a header a service cannot read is not a licence to return
 * every row.
 */
export const parseScope = (headers?: RequestHeaders): Scope => {
  const raw = headerValue(headers);
  const scope: Scope = new Map();
  for (const part of String(raw ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    const type = part.slice(0, eq).trim();
    const list = part.slice(eq + 1);
    scope.set(type, {
      all: list === '*',
      ids: list === '*' || list === '' ? [] : list.split(','),
    });
  }
  return scope;
};

/**
 * The ids of one type a caller may see, or undefined for no restriction. An
 * empty array means nothing is visible, which readers must not confuse with
 * undefined. Anything that is not a scope raises: the absence of a scope on a
 * request that reached the gateway means the request lost its authorization,
 * and returning every row would be the worst possible reading of that.
 */
export const idsInScope = (scope: Scope | typeof UNRESTRICTED, type: string): string[] | undefined => {
  if (scope === UNRESTRICTED) return undefined;
  if (!(scope instanceof Map)) {
    throw new Error('no scope on this request; internal callers must pass UNRESTRICTED');
  }
  const visible = scope.get(type);
  if (!visible) return [];
  return visible.all ? undefined : visible.ids;
};
