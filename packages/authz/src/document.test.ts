import { describe, expect, it } from 'vitest';

import { DocumentError, readDocument, RESOURCES } from '~/document';

const doc = (paths: Record<string, unknown>) => ({ openapi: '3.1.0', info: { title: 't', version: '1' }, paths });

const op = (operationId: string, authz?: unknown) => ({
  operationId,
  summary: operationId,
  ...(authz !== undefined ? { 'x-authz': authz } : {}),
  responses: { 200: { description: 'ok' } },
});

describe('an operation taking over one that is gone', () => {
  it('reads what it replaces', () => {
    const { operations } = readDocument(doc({ '/v2/orders/{order}': { get: op('fetchOrder', { replaces: ['getOrder'] }) } }));
    expect(operations[0]).toMatchObject({ operationId: 'fetchOrder', replaces: ['getOrder'] });
  });

  it('replaces nothing unless it says so', () => {
    const { operations } = readDocument(doc({ '/orders': { post: op('createOrder') } }));
    expect(operations[0]!.replaces).toEqual([]);
  });

  it.each([
    ['itself', { '/o': { get: op('getOrder', { replaces: ['getOrder'] }) } }, /names the operation itself/],
    [
      'one the document still declares',
      { '/o': { get: op('getOrder') }, '/p': { get: op('fetchOrder', { replaces: ['getOrder'] }) } },
      /which the document still declares/,
    ],
    [
      'one another operation already takes over',
      { '/o': { get: op('a', { replaces: ['old'] }) }, '/p': { get: op('b', { replaces: ['old'] }) } },
      /names old on two operations/,
    ],
    ['from an internal operation', { '/h': { get: op('health', { internal: true, replaces: ['old'] }) } }, /replaces none/],
    ['as anything but a list of ids', { '/o': { get: op('getOrder', { replaces: 'old' }) } }, /must be a list of operationIds/],
  ])('refuses replacing %s', (_label, paths, message) => {
    expect(() => readDocument(doc(paths))).toThrow(DocumentError);
    expect(() => readDocument(doc(paths))).toThrow(message);
  });
});

describe('an operation scoped by every resource name the deployment declares', () => {
  it('reads $resources apart from the types it names itself', () => {
    const { operations } = readDocument(doc({ '/grants': { post: op('grant', { scopedBy: ['roles', RESOURCES] }) } }));
    expect(operations[0]).toMatchObject({ scopedBy: [{ type: 'roles' }], resources: true });
  });

  it('is scoped by no more than it names without it', () => {
    const { operations } = readDocument(doc({ '/grants': { post: op('grant', { scopedBy: ['roles'] }) } }));
    expect(operations[0]!.resources).toBe(false);
  });

  it.each([
    ['another word starting with $', { scopedBy: ['$all'] }, /a type never starts with \$/],
    ['$resources bound to a parameter', { scopedBy: [{ $resources: 'grant' }] }, /\$resources stands alone/],
  ])('refuses %s', (_label, authz, message) => {
    expect(() => readDocument(doc({ '/grants/{grant}': { get: op('getGrant', authz) } }))).toThrow(message);
  });
});
