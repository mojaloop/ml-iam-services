import { JsonPointer } from 'json-ptr';

import { Header, JSON_MEDIA } from '../api/vocabulary';
import { ResourceNames, ResourceSource } from '../authzgen/compose';
import { idProblem } from '../authzgen/reserved';
import { Logged } from '../logged';

/**
 * The ids a resource name's declared source lists, read when someone needs
 * them: a picker of that name, or an assignment over one of its ids. Nothing
 * reads a source between requests, and nothing needs the source to announce
 * a change. Readers arriving while a read is under way share it. A read that
 * fails is answered by the last good one, named stale, with the reason.
 */

/** The response did not have the declared shape. */
export class SourceShapeError extends Error {}

/** The ids a source's response carries, by its declared pointers. */
export const idsFrom = (body: unknown, resourceName: string, source: ResourceSource): string[] => {
  const list = source.list ?? '';
  const rows = JsonPointer.get(body, list);
  if (!Array.isArray(rows)) {
    throw new SourceShapeError(`${resourceName}: ${source.url} answered no array at pointer "${list}"`);
  }
  return rows.map((row, index) => {
    const id = JsonPointer.get(row, source.id);
    if (typeof id !== 'string' && typeof id !== 'number') {
      throw new SourceShapeError(`${resourceName}: item ${index} has no id at pointer "${source.id}"`);
    }
    return String(id);
  });
};

export interface Listed {
  ids: string[];
  /** When the read these ids come from happened, if one ever succeeded. */
  read?: string;
  /** Set when the source did not answer as declared, and these ids are its last good read. */
  stale?: { reason: string; since?: string; misdeclared?: true };
}

export class ResourceSources {
  private readonly last = new Map<string, { ids: string[]; at: string }>();
  private readonly reading = new Map<string, Promise<Listed>>();

  constructor(
    private readonly names: () => ResourceNames,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  /** The resource names that declare a source. */
  declared(): string[] {
    return Object.entries(this.names().resourceNames ?? {})
      .filter(([, declared]) => declared.source !== undefined)
      .map(([name]) => name);
  }

  /** What the name's source lists now, or nothing for a name that declares none. */
  async ids(resourceName: string): Promise<Listed | undefined> {
    const source = this.names().resourceNames?.[resourceName]?.source;
    if (source === undefined) return undefined;
    const running = this.reading.get(resourceName);
    if (running !== undefined) return running;
    const read = this.read(resourceName, source).finally(() => this.reading.delete(resourceName));
    this.reading.set(resourceName, read);
    return read;
  }

  private async read(resourceName: string, source: ResourceSource): Promise<Listed> {
    try {
      const response = await this.fetchImpl(source.url, { headers: { [Header.accept]: JSON_MEDIA } });
      if (!response.ok) throw new Error(`${resourceName}: ${source.url} answered ${response.status}`);
      const listed = idsFrom(await response.json(), resourceName, source);
      const refused = listed.flatMap((id) => {
        const problem = idProblem(id);
        return problem === undefined ? [] : [problem];
      });
      if (refused.length > 0) console.error(JSON.stringify({ event: Logged.sourceIdsRefused, resourceName, refused }));
      const ids = [...new Set(listed.filter((id) => idProblem(id) === undefined))];
      const read = new Date().toISOString();
      this.last.set(resourceName, { ids, at: read });
      return { ids, read };
    } catch (error) {
      const reason = (error as Error).message;
      console.error(JSON.stringify({ event: Logged.sourceReadFailed, resourceName, error: reason }));
      const kept = this.last.get(resourceName);
      return {
        ids: kept?.ids ?? [],
        ...(kept !== undefined ? { read: kept.at } : {}),
        stale: {
          reason,
          ...(kept !== undefined ? { since: kept.at } : {}),
          ...(error instanceof SourceShapeError ? { misdeclared: true as const } : {}),
        },
      };
    }
  }
}
