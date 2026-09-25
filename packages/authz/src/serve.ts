/**
 * Where the platform reads a service's API document.
 *
 * A guard hands over the document it was built from, on the service's own
 * server, so the surface the platform authorizes is the one the service is
 * enforcing: whichever file its config selected, whichever copy its resolver
 * landed on, whatever its framework assembled.
 *
 * The contract is HTTP, not this package. A GET on the path answers 200 with
 * the document as `application/json` and an `ETag` over exactly those bytes;
 * `If-None-Match` on that value answers 304, and any other method answers 405.
 * Anything that speaks HTTP satisfies it, in any language, with or without
 * this package.
 *
 * A handler either returns a value or writes the response, and a guard carries
 * what each shape needs:
 *
 *   returns a value   `authz.document`, serialized by the framework
 *   writes a response `authz.published.body` and `.etag`, written verbatim
 *   express-shaped    `authz.expose()`, which also passes other paths on
 *
 * The path is the same everywhere, so a service names it nowhere and the
 * gateway refuses it on every route from one rule. Nothing reaches it from
 * outside: the operator reads it in the cluster, through the Service.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';

/** The path the platform reads a document at, on the service's own port. */
export const DOCUMENT_PATH = '/.authz/openapi';

/** What a server answers with, for one that routes the document itself. */
export interface Published {
  /** The exact bytes, so a framework sending its own response sends these. */
  body: Buffer;
  /** The digest of those bytes, which the platform reads to skip an unchanged fetch. */
  etag: string;
}

/**
 * Answers for the document and passes everything else on, so it mounts ahead
 * of a router that would refuse a path its own document does not describe.
 */
export type Exposed = (req: IncomingMessage, res: ServerResponse, next?: () => void) => void;

const pathOf = (url: string | undefined): string => new URL(url ?? '/', 'http://document').pathname;

/** Renders one parsed document, read once. */
export const publish = (doc: unknown): Published => {
  const body = Buffer.from(JSON.stringify(doc));
  return { body, etag: `"${createHash('sha256').update(body).digest('hex')}"` };
};

export const exposeDocument = ({ body, etag }: Published): Exposed => {
  return (req, res, next) => {
    if (pathOf(req.url) !== DOCUMENT_PATH) {
      if (next) return next();
      res.writeHead(404);
      res.end();
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' });
      res.end();
      return;
    }
    if (req.headers['if-none-match'] === etag) {
      res.writeHead(304, { etag });
      res.end();
      return;
    }
    res.writeHead(200, {
      'content-type': 'application/json',
      'content-length': body.length,
      etag,
    });
    res.end(req.method === 'HEAD' ? undefined : body);
  };
};
