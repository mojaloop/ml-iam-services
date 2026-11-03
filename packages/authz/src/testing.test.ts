import { test } from 'vitest';
import assert from 'node:assert/strict';

import { createGuard, Forbidden } from '~/index';
import { caller } from '~/testing';

const doc = {
  openapi: '3.1.0',
  info: { title: 'Sales', version: '1.0.0' },
  servers: [{ url: '/api' }],
  components: { securitySchemes: { session: { type: 'apiKey', in: 'cookie', name: 'ory_kratos_session' } } },
  paths: {
    '/orders': {
      get: {
        operationId: 'getOrders',
        summary: 'Lists orders',
        security: [{ session: [] }],
        'x-authz': { scopedBy: ['orders', 'customers'] },
        responses: { '200': { description: 'ok', content: { 'application/json': { schema: { type: 'array' } } } } },
      },
    },
  },
};

const orders = { method: 'GET', url: '/api/orders' };
const rows = [{ id: 'o1' }, { id: 'o2' }, { id: 'o3' }];
const idOf = (row: { id: string }) => row.id;

test("a caller reaching some ids is answered those by the service's guard, and by access", async () => {
  const guard = await createGuard(doc);
  const operator = caller().reaching('orders', ['o1', 'o3']);
  for (const answer of [guard({ ...orders, ...operator.request }, 'orders'), operator.access('orders'), operator.guard({}, 'orders')]) {
    assert.equal(answer.restricted, true);
    assert.deepEqual(answer.ids, ['o1', 'o3']);
    assert.deepEqual(answer.narrow(rows, idOf), [{ id: 'o1' }, { id: 'o3' }]);
  }
});

test("a caller reaching every id is answered everything by the service's guard, and by access", async () => {
  const guard = await createGuard(doc);
  const hub = caller().reachingAll('orders');
  for (const answer of [guard({ ...orders, ...hub.request }, 'orders'), hub.access('orders'), hub.guard({}, 'orders')]) {
    assert.equal(answer.restricted, false);
    assert.equal(answer.allows('o2'), true);
    assert.deepEqual(answer.narrow(rows, idOf), rows);
  }
});

test("a caller reaching none of a type is refused by the service's guard, and by access", async () => {
  const guard = await createGuard(doc);
  for (const nobody of [caller(), caller().reaching('orders', []), caller().reachingAll('customers')]) {
    assert.throws(() => guard({ ...orders, ...nobody.request }, 'orders'), Forbidden);
    assert.throws(() => nobody.access('orders'), Forbidden);
    assert.throws(() => nobody.guard({}, 'orders'), Forbidden);
  }
});

test('reaching more adds to a caller, and leaves the caller it came from as it was', async () => {
  const guard = await createGuard(doc);
  const one = caller().reaching('orders', ['o1']);
  const both = one.reaching('orders', ['o3']).reachingAll('customers');
  assert.deepEqual(guard({ ...orders, ...both.request }, 'orders').ids, ['o1', 'o3']);
  assert.equal(guard({ ...orders, ...both.request }, 'customers').restricted, false);
  assert.deepEqual(guard({ ...orders, ...one.request }, 'orders').ids, ['o1']);
  assert.throws(() => guard({ ...orders, ...one.request }, 'customers'), Forbidden);
  assert.equal(guard({ ...orders, ...one.reaching('orders', ['o2']).reachingAll('orders').request }, 'orders').restricted, false);
});

test('an id a request cannot carry is refused rather than reaching something else', () => {
  assert.throws(() => caller().reaching('orders', ['o1,o2']), /separate ids/);
  assert.throws(() => caller().reaching('orders', ['o1;customers=acme']), /separate ids/);
  assert.throws(() => caller().reaching('orders', ['$all']), /reserved words/);
});

test('ids not given as a list are refused rather than read as reaching none', () => {
  const unchecked = caller() as unknown as { reaching(type: string, ids?: unknown): unknown };
  assert.throws(() => unchecked.reaching('orders'), /takes its ids as a list/);
  assert.throws(() => unchecked.reaching('orders', 'o1'), /takes its ids as a list/);
});
