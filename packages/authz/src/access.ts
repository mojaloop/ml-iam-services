/**
 * What a caller may reach of one type, read from the scope a request carries.
 * Private to this package: the guard and the test callers both answer through
 * `accessIn`, so a test caller is handed exactly what a handler would be.
 */

import { idsInScope, type Scope } from '~/header';

/** What a caller may reach of one resource type. */
export interface Access {
  /** Whether anything limits this caller. */
  restricted: boolean;
  /** The ids it may reach; empty when nothing restricts it. */
  ids: string[];
  /** Whether this caller may reach one id. */
  allows(id: string): boolean;
  /** The members of a list in hand it may reach. */
  narrow<T>(rows: T[], idOf: (row: T) => string): T[];
}

/** A request the caller may not make. Carries `status` 403 for any framework. */
export class Forbidden extends Error {
  /** What a service's error handler renders, whichever framework it is. */
  readonly status = 403;
  readonly statusCode = 403;
  readonly expose = true;

  constructor(message: string) {
    super(message);
    this.name = 'Forbidden';
  }
}

/**
 * Every id reachable, for a caller nothing restricts. Exported so a service
 * calling its own internals passes it by name, which keeps an unrestricted
 * read something someone wrote rather than something a missing scope caused.
 *
 * `ids` is empty here rather than absent, so a service that builds a query
 * from it without asking `restricted` first shows nothing instead of showing
 * the whole table. The careless branch is the closed one.
 */
export const EVERYTHING: Access = {
  restricted: false,
  ids: [],
  allows: () => true,
  narrow: (rows) => rows,
};

const restrictedTo = (ids: string[]): Access => ({
  restricted: true,
  ids,
  allows: (id) => ids.includes(id),
  narrow: (rows, idOf) => rows.filter((row) => ids.includes(idOf(row))),
});

/** What a caller holding this scope may reach of one type; refuses a caller holding none. */
export const accessIn = (scope: Scope, type: string): Access => {
  const ids = idsInScope(scope, type);
  if (ids === undefined) return EVERYTHING;
  if (ids.length === 0) throw new Forbidden(`this caller may reach no ${type}`);
  return restrictedTo(ids);
};
