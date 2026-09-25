/**
 * The platform's side of the contract: turning a decision into what a service
 * will be able to read with `createGuard`.
 *
 * Only the endpoint that makes the decision imports this. A service never
 * does, which is what keeps the header and its format out of every codebase
 * but this one.
 */

export { HEADER, NONE, formatScope, scopeHeaders, parseScope } from '~/header';
export type { Scope, ScopeEntry, RequestHeaders } from '~/header';
