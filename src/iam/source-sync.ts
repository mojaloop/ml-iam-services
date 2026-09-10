import { JsonPointer } from 'json-ptr';

import { ResourceNames, ResourceSource } from '../authzgen/compose';
import { Tuple } from './materialize';
import { EXISTS, parseResource, RESOURCE_NAMESPACE, SOURCED, sourcedTuple } from './registry';

/**
 * Keeps the registry holding what a noun's source answers: each id the source
 * lists exists under every spelling the noun's members give it, and only
 * those. The rows carry their own marker, so reconciling them can never touch
 * a row a service provisioned, and every reader of the registry accepts
 * either marker.
 */

/** The response did not have the declared shape: configuration, so it stops a start. */
export class SourceShapeError extends Error {}

export interface SyncTarget {
  resourceName: string;
  source: ResourceSource;
}

export const targetsOf = (names: ResourceNames): SyncTarget[] =>
  Object.entries(names.resourceNames ?? {})
    .filter(([, declared]) => declared.source !== undefined)
    .map(([resourceName, declared]) => ({
      resourceName,
      source: declared.source!,
    }));

/** The ids a source's response carries, by its declared pointers. */
export const idsFrom = (body: unknown, target: SyncTarget): string[] => {
  const list = target.source.list ?? '';
  const rows = JsonPointer.get(body, list);
  if (!Array.isArray(rows)) {
    throw new SourceShapeError(`${target.resourceName}: ${target.source.url} answered no array at pointer "${list}"`);
  }
  return rows.map((row, index) => {
    const id = JsonPointer.get(row, target.source.id);
    if (typeof id !== 'string' && typeof id !== 'number') {
      throw new SourceShapeError(`${target.resourceName}: item ${index} has no id at pointer "${target.source.id}"`);
    }
    return String(id);
  });
};

interface RegistryStore {
  query(params: Record<string, string>): Promise<Tuple[]>;
  putAll(tuples: Tuple[]): Promise<void>;
  deleteWhere(params: Record<string, string>): Promise<void>;
}

/**
 * One pass for one resource name: fetch the list, and make its sourced rows
 * exactly it. The source is the resource name's authority, so an id it no
 * longer lists is a resource that no longer exists to be granted.
 */
export async function syncTarget(
  target: SyncTarget,
  keto: RegistryStore,
  fetchImpl: typeof fetch = fetch,
): Promise<{ added: string[]; removed: string[] }> {
  const response = await fetchImpl(target.source.url, { headers: { accept: 'application/json' } });
  if (!response.ok) throw new Error(`${target.resourceName}: ${target.source.url} answered ${response.status}`);
  const ids = new Set(idsFrom(await response.json(), target));

  const rows = await keto.query({
    namespace: RESOURCE_NAMESPACE,
    relation: EXISTS,
    subject_id: SOURCED,
  });
  const held = new Set<string>();
  for (const row of rows) {
    const parsed = parseResource(row.object);
    if (parsed !== undefined && parsed.resourceName === target.resourceName) held.add(parsed.id);
  }

  const added: string[] = [];
  const removed: string[] = [];
  const puts: Tuple[] = [];
  for (const id of ids) {
    if (!held.has(id)) {
      puts.push(sourcedTuple(target.resourceName, id));
      added.push(`${target.resourceName}/${id}`);
    }
  }
  for (const id of held) {
    if (!ids.has(id)) removed.push(`${target.resourceName}/${id}`);
  }

  await keto.putAll(puts);
  for (const object of removed) {
    await keto.deleteWhere({
      namespace: RESOURCE_NAMESPACE,
      object,
      relation: EXISTS,
      subject_id: SOURCED,
    });
  }
  return { added: added.sort(), removed: removed.sort() };
}

export interface SourceSyncOptions {
  names: ResourceNames;
  keto: RegistryStore;
  intervalMs: number;
  fetchImpl?: typeof fetch;
}

/**
 * The first pass runs before this returns, so a source whose declared shape
 * does not match what it answers stops the start instead of serving a picker
 * beside an empty registry. Later passes absorb failures and keep the last
 * synced rows: a source being down is the one thing an interval retries.
 */
export async function startSourceSync(options: SourceSyncOptions): Promise<{ stop: () => void }> {
  const targets = targetsOf(options.names);
  const pass = async (initial: boolean): Promise<void> => {
    for (const target of targets) {
      try {
        const { added, removed } = await syncTarget(target, options.keto, options.fetchImpl);
        if (added.length > 0 || removed.length > 0 || initial) {
          console.log(JSON.stringify({ event: 'source-sync', resourceName: target.resourceName, added, removed }));
        }
      } catch (error) {
        if (initial && error instanceof SourceShapeError) throw error;
        console.error(`source-sync ${target.resourceName}: ${(error as Error).message}`);
      }
    }
  };

  await pass(true);
  const timer = setInterval(() => void pass(false), options.intervalMs);
  timer.unref?.();
  return { stop: () => clearInterval(timer) };
}
