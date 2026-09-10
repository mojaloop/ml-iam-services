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

/** A call with no gateway in the path: one service calling another, a job, a test. */
export const UNRESTRICTED: unique symbol;

/** Access nothing restricts, for a service calling its own internals. */
export const EVERYTHING: Access;

/** Access limited to these ids, for a service naming a subset itself. */
export function restrictedTo(ids: string[]): Access;

/** A request the caller may not make. Carries `status` 403 for any framework. */
export class Forbidden extends Error {
  status: 403;
  statusCode: 403;
  expose: true;
}

/** A service asking something its own document does not describe. */
export class GuardError extends Error {}

export type Guard = ((req: unknown | typeof UNRESTRICTED, type: string) => Access) & {
  /** The service the document names. */
  service: string;
  /** The types this request's operation hands the service to narrow its own answer by. */
  scopedBy(req: unknown | typeof UNRESTRICTED): string[];
};

/**
 * Reads a service's API document and answers, per request, what the caller
 * may see of a resource type that document is scoped by.
 *
 * @param document  a path to the document, or one already parsed
 */
export function createGuard(document: string | object): Promise<Guard>;

/**
 * A guard for a caller that reaches exactly this, by type. Whatever stands in
 * for a decision — a job that runs for one participant, a test — builds one
 * here, so what a guard is made of stays in this package.
 */
export function guardReaching(access: Record<string, Access>, service?: string): Guard;
