import { ketoNamespace } from './keto-name';
import { ServiceBundle } from './types';

/**
 * The Ory Permission Language model: one namespace per service.
 *
 * Keto takes namespace existence from this file and everything else from
 * tuples. Subject sets resolve natively, so a grant held by a role's members
 * evaluates as stored data; grant points are relation names on the object;
 * and the type-wide object and named sets are reached by checking those
 * objects directly.
 *
 * Objects carry both type and id, so one namespace serves every resource
 * type a service has: `<service>:<type>/<id>` for a resource,
 * `<type>/__all__` for the type-wide object, `__self__` for the singleton.
 */

/** Declared once per deployment; every staged model repeats them byte-identically. */
export const CANONICAL_STUBS = `import { Namespace } from "@ory/keto-namespace-types"

export class User implements Namespace {}

export class Role implements Namespace {
  // @ts-ignore TS2564: OPL declaration, never instantiated
  related: {
    members: User[]
  }
}

// Which resources exist, so an operator can be offered them by name. A
// deployment-level fact: a report outlives the rollout that introduced it.
export class Resource implements Namespace {}
`;

/** A service's namespace declaration. */
export function emitNamespace(bundle: ServiceBundle): string {
  return (
    `// ${bundle.title}: objects are "<type>/<id>", "<type>/__all__" for the\n` +
    `// type-wide object, "__self__" for the service singleton.\n` +
    `export class ${ketoNamespace(bundle.service)} implements Namespace {}\n`
  );
}

export function emitModel(bundle: ServiceBundle, includeStubs = true): string {
  const namespace = emitNamespace(bundle);
  return includeStubs ? `${CANONICAL_STUBS}\n${namespace}` : namespace;
}
