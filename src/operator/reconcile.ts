import { emitCatalog, generate } from '../authzgen';
import {
  compose,
  ComposedService,
  Composition,
  diffCatalogs,
  Migrations,
  ResourceNames,
  ungated,
} from '../authzgen/compose';
import { ServiceCatalog } from '../authzgen/types';

/**
 * One reading of what this deployment's services declare, whatever declared it.
 *
 * A document arrives from a file the chart mounted or from a custom resource
 * its own operator wrote, and the two are the same fact: this service, served
 * here, describes this surface. Reconciling them together is what lets a helm
 * upgrade and a `kubectl apply` reach the gateway by the same path, with the
 * same checks and the same refusal.
 */

/** A document to compose, from whichever source produced it. */
export interface Declared {
  /** Where it came from, for a message an operator can act on. */
  origin: string;
  /** The parsed OpenAPI document. */
  document: unknown;
  /** Where the service is served, which the gateway rules match on. */
  serving: { host?: string; path?: string };
}

export interface Reconciled {
  /** What every source together describes, when they agree. */
  composition?: Composition;
  /** Why this reconcile changed nothing, when it did not. */
  problems: string[];
  /** Which origins were read. */
  origins: string[];
}

/**
 * Composes what the sources declare and refuses the result if anything is
 * wrong with it. A refusal changes nothing: the caller keeps serving what it
 * last accepted, because a rollout that publishes half a deployment's rules
 * is a gateway that answers 404 for the other half.
 */
export function reconcile(
  declared: Declared[],
  names: ResourceNames = {},
  published?: ServiceCatalog[],
  migrations: Migrations = {},
): Reconciled {
  const problems: string[] = [];
  const services: ComposedService[] = [];

  for (const entry of declared) {
    try {
      const result = generate(entry.document, entry.serving, names);
      services.push({
        bundle: result.bundle,
        rules: result.rules,
        catalog: emitCatalog(result.bundle),
        derivation: result.derivation,
        ...entry.serving,
      });
    } catch (error) {
      problems.push(`${entry.origin}: ${(error as Error).message}`);
    }
  }

  if (problems.length > 0) return { problems, origins: declared.map((d) => d.origin) };

  const composition = compose(services, names);
  if (composition.problems.length > 0) {
    return { problems: composition.problems, origins: declared.map((d) => d.origin) };
  }

  // A permission that changed shape or left is a grant that silently means
  // something else, or nothing. The deployment says what happens to those
  // before the change reaches the gateway.
  if (published !== undefined) {
    const changes = diffCatalogs(published, composition.catalog);
    const unresolved = ungated(changes, migrations);
    if (unresolved.length > 0) {
      return { problems: unresolved, origins: declared.map((d) => d.origin) };
    }
  }

  return { composition, problems: [], origins: declared.map((d) => d.origin) };
}
