import { test, onTestFinished } from 'vitest';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createGuard, DOCUMENT_PATH } from '~/index';

const doc = {
  openapi: '3.1.0',
  info: { title: 'Sales', version: '1.0.0' },
  servers: [{ url: '/api' }],
  paths: {
    '/orders/{orderId}': {
      get: {
        operationId: 'getOrder',
        summary: 'Reads one order',
        security: [{ session: [] }],
        responses: { '200': { description: 'ok' } },
      },
    },
  },
};

/** The service's own server, with the document mounted the way an adopter mounts it. */
const serving = async (document: string | object, fallback?: http.RequestListener) => {
  const authz = await createGuard(document);
  const expose = authz.expose();
  const server = http.createServer((req, res) => expose(req, res, fallback && (() => fallback(req, res))));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  onTestFinished(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const { port } = server.address() as { port: number };
  return { url: `http://127.0.0.1:${port}`, authz };
};

test('a guard hands over the document it was built from', async () => {
  const { url } = await serving(doc);

  const response = await fetch(`${url}${DOCUMENT_PATH}`);

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'application/json');
  assert.deepEqual(await response.json(), doc);
});

test('a guard built from a path hands over what it read', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'authz-')), 'openapi.json');
  fs.writeFileSync(file, JSON.stringify(doc));

  const { url } = await serving(file);

  assert.deepEqual(await (await fetch(`${url}${DOCUMENT_PATH}`)).json(), doc);
});

test('the etag digests the body, so an unchanged document answers 304', async () => {
  const { url } = await serving(doc);

  const first = await fetch(`${url}${DOCUMENT_PATH}`);
  const etag = first.headers.get('etag');
  assert.match(String(etag), /^"[0-9a-f]{64}"$/);

  const again = await fetch(`${url}${DOCUMENT_PATH}`, { headers: { 'if-none-match': String(etag) } });
  assert.equal(again.status, 304);
});

test('two documents digest differently', async () => {
  const one = await serving(doc);
  const other = await serving({ ...doc, info: { title: 'Shipping', version: '1.0.0' } });

  const etagOf = async (url: string) => (await fetch(`${url}${DOCUMENT_PATH}`)).headers.get('etag');

  assert.notEqual(await etagOf(one.url), await etagOf(other.url));
});

test('a HEAD carries the headers and no body', async () => {
  const { url } = await serving(doc);

  const response = await fetch(`${url}${DOCUMENT_PATH}`, { method: 'HEAD' });

  assert.equal(response.status, 200);
  assert.match(String(response.headers.get('etag')), /^"[0-9a-f]{64}"$/);
  assert.equal(await response.text(), '');
});

test('the document answers only to a read', async () => {
  const { url } = await serving(doc);

  assert.equal((await fetch(`${url}${DOCUMENT_PATH}`, { method: 'POST' })).status, 405);
});

/**
 * The reason this mounts as a handler rather than a route: a router generated
 * from the document would refuse a path the document does not describe.
 */
test('every other path carries on to the service', async () => {
  const { url } = await serving(doc, (_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('the service answered');
  });

  const response = await fetch(`${url}/api/orders/o1`);

  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'the service answered');
});

test('a service mounting nothing after it refuses every other path', async () => {
  const { url } = await serving(doc);

  assert.equal((await fetch(`${url}/api/orders/o1`)).status, 404);
});

/**
 * The contract is the response, not the handler: a framework with its own
 * routing — hapi, fastify, or a server in another language — answers the same
 * path itself and the platform cannot tell the difference.
 */
test('a server routing the document itself answers identically', async () => {
  const authz = await createGuard(doc);
  const server = http.createServer((req, res) => {
    if (req.url !== authz.path) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', etag: authz.published.etag });
    res.end(authz.published.body);
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  onTestFinished(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const { port } = server.address() as { port: number };

  const mounted = await serving(doc);
  const own = await fetch(`http://127.0.0.1:${port}${DOCUMENT_PATH}`);
  const viaHandler = await fetch(`${mounted.url}${DOCUMENT_PATH}`);

  assert.deepEqual(await own.json(), await viaHandler.json());
  assert.equal(own.headers.get('etag'), viaHandler.headers.get('etag'));
  assert.equal(authz.document, doc);
});
