import { RESERVED } from '@mojaloop/authz/reserved';

/**
 * The IAM's own words, beside the ones the platform reserves. Every one
 * starts with the platform's reserved prefix, which no resource id may, so a
 * reserved word and an id can never be read for each other, and a word added
 * later collides with nothing already stored.
 */

export { ALL, idProblem, RESERVED } from '@mojaloop/authz/reserved';

/** The object a permission naming no resource is checked on. */
export const SINGLETON = `${RESERVED}self` as const;

/** The subject every authenticated subject is, for the roles they all hold. */
export const AUTHENTICATED = `${RESERVED}authenticated` as const;

/** Who recorded a resource: a service, through the IAM. */
export const REGISTRY = `${RESERVED}registry` as const;
