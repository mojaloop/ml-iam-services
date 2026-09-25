import { DOCUMENT_PATH } from '@mojaloop/authz';

import { readSpec } from '../authzgen';

/**
 * Where a backend's document comes from: the backend itself, answering the
 * document path through its Service, or an AuthzDocument its route names. Both
 * are read by the same reader, so nothing downstream can tell which answered.
 */

/** The shape of an AuthzDocument, as its custom resource definition declares it. */
export interface AuthzDocumentResource {
  metadata?: { name?: string; namespace?: string; generation?: number };
  spec?: { document?: Record<string, unknown> };
}

export const documentId = (resource: AuthzDocumentResource): string =>
  `${resource.metadata?.namespace ?? 'default'}/${resource.metadata?.name ?? '(unnamed)'}`;

/** Reads the document an AuthzDocument carries. */
export async function fromResource(resource: AuthzDocumentResource): Promise<unknown> {
  const id = documentId(resource);
  const document = resource.spec?.document;
  if (document === undefined || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error(`AuthzDocument/${id}: spec.document is not an OpenAPI document`);
  }
  return readSpec(document, `AuthzDocument/${id}`);
}

/** A request that takes longer than this is a backend that is not answering. */
const TIMEOUT_MS = 10_000;

interface Fetched {
  etag?: string;
  document: unknown;
}

/**
 * Reads what backends serve, remembering each answer's ETag so an unchanged
 * document costs a 304 rather than a re-read.
 */
export class ServedDocuments {
  private readonly seen = new Map<string, Fetched>();

  /** The URL a backend answers its document on, inside the cluster. */
  static urlOf(namespace: string, name: string, port: number): string {
    return `http://${name}.${namespace}.svc:${port}${DOCUMENT_PATH}`;
  }

  async read(url: string): Promise<unknown> {
    const known = this.seen.get(url);
    const response = await fetch(url, {
      headers: known?.etag !== undefined ? { 'if-none-match': known.etag } : {},
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (response.status === 304 && known !== undefined) return known.document;
    if (!response.ok) throw new Error(`${url} answered ${response.status}`);

    const body = (await response.json()) as Record<string, unknown>;
    const document = await readSpec(body, url);
    const etag = response.headers.get('etag') ?? undefined;
    this.seen.set(url, { document, ...(etag !== undefined ? { etag } : {}) });
    return document;
  }
}
