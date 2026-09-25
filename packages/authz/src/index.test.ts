import { test } from 'vitest';
import assert from 'node:assert/strict';

import { createGuard, guardReaching, restrictedTo, EVERYTHING, UNRESTRICTED, Forbidden, GuardError } from '~/index';

/** Fixtures are written malformed on purpose, so nothing here is typed. */
type Fixture = Record<string, any>;

const doc: Fixture = {
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
        'x-authz': { scopedBy: ['orders'] },
        responses: { '200': { description: 'ok', content: { 'application/json': { schema: { type: 'array' } } } } },
      },
    },
    '/orders/{orderId}/status': {
      get: {
        operationId: 'getOrderStatus',
        summary: "Reads one order's status",
        security: [{ session: [] }],
        responses: { '200': { description: 'ok' } },
      },
    },
    '/health': {
      get: { operationId: 'getHealth', summary: 'Health', security: [], responses: { '200': { description: 'ok' } } },
    },
  },
};

const req = (url: string, scope?: string, method = 'GET') => ({
  method,
  url,
  headers: scope === undefined ? {} : { 'x-scope': scope },
});

test('a caller nothing restricts sees everything', async () => {
  const guard = await createGuard(doc);
  const orders = guard(req('/api/orders', 'orders=*'), 'orders');
  assert.equal(orders.restricted, false);
  assert.equal(orders.allows('anything'), true);
  assert.deepEqual(orders.narrow([{ id: 'o1' }, { id: 'o2' }], (row) => row.id), [{ id: 'o1' }, { id: 'o2' }]);
});

test('a caller holding some sees those, and narrows a list to them', async () => {
  const guard = await createGuard(doc);
  const orders = guard(req('/api/orders', 'orders=o1,o3'), 'orders');
  assert.equal(orders.restricted, true);
  assert.deepEqual(orders.ids, ['o1', 'o3']);
  assert.equal(orders.allows('o1'), true);
  assert.equal(orders.allows('o2'), false);
  assert.deepEqual(
    orders.narrow([{ id: 'o1' }, { id: 'o2' }, { id: 'o3' }], (row) => row.id),
    [{ id: 'o1' }, { id: 'o3' }],
  );
});

/**
 * The state a service forgets to ask about must be the safe one: a query
 * built from `ids` alone shows nothing rather than the whole table.
 */
test('the ids of an unrestricted caller are empty, not everything', async () => {
  const guard = await createGuard(doc);
  assert.deepEqual(guard(req('/api/orders', 'orders=*'), 'orders').ids, []);
  assert.deepEqual(guard(UNRESTRICTED, 'orders').ids, []);
});

test('a caller holding none is refused, with a status a framework can render', async () => {
  const guard = await createGuard(doc);
  assert.throws(
    () => guard(req('/api/orders', 'customers=acme'), 'orders'),
    (error: unknown) => error instanceof Forbidden && error.status === 403 && /no orders/.test(error.message),
  );
});

test('a query string does not stop the operation being found', async () => {
  const guard = await createGuard(doc);
  assert.equal(guard(req('/api/orders?limit=20&after=o1', 'orders=*'), 'orders').restricted, false);
});

test('an id the path carries belongs to a caller the gateway let through', async () => {
  const guard = await createGuard(doc);
  const orders = guard(req('/api/orders/o1/status', 'orders=o1'), 'orders');
  assert.deepEqual(orders.ids, ['o1']);
});

test('a call with no gateway in its path passes the sentinel', async () => {
  const guard = await createGuard(doc);
  assert.equal(guard(UNRESTRICTED, 'orders').restricted, false);
});

test('asking about a type the operation is not scoped by is a mistake in the service', async () => {
  const guard = await createGuard(doc);
  assert.throws(() => guard(req('/api/orders', 'orders=*'), 'customers'), GuardError);
});

test('a path the document does not describe is a mistake in the service', async () => {
  const guard = await createGuard(doc);
  assert.throws(() => guard(req('/api/nothing', 'orders=*'), 'orders'), GuardError);
});

test('an unknown x-authz key is refused at startup', async () => {
  const bad: Fixture = structuredClone(doc);
  bad.paths['/orders'].get['x-authz'] = { resources: ['orders'] };
  await assert.rejects(() => createGuard(bad), /unknown x-authz key/);
});

const bound: Fixture = structuredClone(doc);
bound.paths['/customers/{customerId}/orders/{orderId}'] = {
  get: {
    operationId: 'getCustomerOrder',
    summary: 'Reads one order of one customer',
    security: [{ session: [] }],
    'x-authz': { scopedBy: [{ orders: 'orderId' }] },
    responses: { '200': { description: 'ok' } },
  },
};

test('a binding names the parameter the path carries the type its id in', async () => {
  const guard = await createGuard(bound);
  const request = req('/api/customers/acme/orders/o1', 'orders=o1');
  assert.deepEqual(guard.scopedBy(request), []);
  assert.equal(guard(request, 'orders').allows('o1'), true);
});

test('a binding to a parameter the path does not have is refused at startup', async () => {
  const bad: Fixture = structuredClone(bound);
  bad.paths['/customers/{customerId}/orders/{orderId}'].get['x-authz'] = { scopedBy: [{ orders: 'nope' }] };
  await assert.rejects(() => createGuard(bad), /binds orders to \{nope\}/);
});

test('a bare type the path binds is refused, because it would read as unbound', async () => {
  const bad: Fixture = structuredClone(bound);
  bad.paths['/customers/{customerId}/orders/{orderId}'].get['x-authz'] = { scopedBy: ['orders'] };
  await assert.rejects(() => createGuard(bad), /the path binds orders through \{orderId\}/);
});

test('a guard can be built from what a caller reaches, for whatever stands in for a decision', () => {
  const guard = guardReaching({ orders: restrictedTo(['o1']), customers: EVERYTHING });
  assert.deepEqual(guard.scopedBy().sort(), ['customers', 'orders']);
  assert.equal(guard({}, 'orders').allows('o1'), true);
  assert.equal(guard({}, 'orders').allows('o2'), false);
  assert.equal(guard({}, 'customers').restricted, false);
});

test('a guard built from what a caller reaches refuses a type it was not given', () => {
  const guard = guardReaching({ orders: EVERYTHING });
  assert.throws(() => guard({}, 'customers'), GuardError);
});

test('a list is a list however its type is written', async () => {
  const union: Fixture = structuredClone(doc);
  delete union.paths['/orders'].get['x-authz'];
  union.paths['/orders'].get.responses['200'].content['application/json'].schema = { type: ['array', 'null'] };
  await assert.rejects(() => createGuard(union), /returns a list and binds no resource id/);
});

const everyMethod: Fixture = structuredClone(doc);
everyMethod.paths['/orders'].trace = {
  operationId: 'traceOrders',
  summary: 'Traces the orders endpoint',
  security: [{ session: [] }],
  responses: { '200': { description: 'ok' } },
};
everyMethod.paths['/orders'].additionalOperations = {
  PURGE: {
    operationId: 'purgeOrders',
    summary: 'Purges the orders cache',
    security: [{ session: [] }],
    responses: { '200': { description: 'ok' } },
  },
};

test('a method with no fixed field of its own is still an operation', async () => {
  const guard = await createGuard(everyMethod);
  assert.deepEqual(guard.scopedBy(req('/api/orders', 'orders=*', 'TRACE')), []);
  assert.deepEqual(guard.scopedBy(req('/api/orders', 'orders=*', 'PURGE')), []);
});

test('a scopedBy entry that is neither a type nor one binding is refused at startup', async () => {
  const bad: Fixture = structuredClone(bound);
  bad.paths['/customers/{customerId}/orders/{orderId}'].get['x-authz'] = {
    scopedBy: [{ orders: 'orderId', customers: 'customerId' }],
  };
  await assert.rejects(() => createGuard(bad), /a scopedBy entry is a type, or one/);
});
