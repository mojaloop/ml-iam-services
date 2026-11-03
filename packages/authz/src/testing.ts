/**
 * Callers for a service's tests, said in the service's own terms: which ids
 * of which of its types a caller reaches. How a decision travels and what a
 * guard is made of stay in this package, so a test hands a caller over and
 * never reads it.
 *
 *   const operator = caller().reaching('orders', ['o1', 'o3']);
 *   const hub = caller().reachingAll('orders');
 *
 *   await fetch(url, operator.request)          // the service's own guard decides
 *   orders.list(hub.access('orders'))           // what that guard hands a handler
 *   handler({ ...req, authz: operator.guard })  // what fills the guard's slot
 *
 * Every answer is read back from the request the caller hands out, so it is
 * the answer the service's guard gives for that request.
 */

import { parseScope, scopeHeaders, type Scope } from '~/header';
import { accessIn, type Access } from '~/access';
import { idProblem } from '~/reserved';

export interface Caller {
  /** This caller, reaching these ids of a type as well; an empty list reaches none of them. */
  reaching(type: string, ids: string[]): Caller;
  /** This caller, reaching every id of a type. */
  reachingAll(type: string): Caller;
  /** What a request carries for the service's guard to see this caller. */
  readonly request: { headers: Record<string, string> };
  /** What the guard hands a handler of one type; refuses a caller reaching none. */
  access(type: string): Access;
  /** A guard that answers for this caller whatever the request. */
  readonly guard: (req: unknown, type: string) => Access;
}

const build = (scope: Scope): Caller => {
  const access = (type: string): Access => accessIn(parseScope(scopeHeaders(scope)), type);
  const add = (type: string, all: boolean, ids: string[]): Caller => {
    const held = scope.get(type);
    return build(
      new Map(scope).set(type, { all: all || (held?.all ?? false), ids: [...new Set([...(held?.ids ?? []), ...ids])] }),
    );
  };
  return {
    reaching: (type, ids) => {
      if (!Array.isArray(ids)) throw new TypeError(`reaching ${type} takes its ids as a list`);
      for (const id of ids) {
        const problem = idProblem(id);
        if (problem !== undefined) throw new Error(problem);
      }
      return add(type, false, ids);
    },
    reachingAll: (type) => add(type, true, []),
    get request() {
      return { headers: scopeHeaders(scope) };
    },
    access,
    guard: (_req, type) => access(type),
  };
};

/** A caller reaching nothing yet. */
export const caller = (): Caller => build(new Map());
