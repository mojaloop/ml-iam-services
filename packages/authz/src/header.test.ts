import { test } from 'vitest';
import assert from 'node:assert/strict';

import {
  NONE,
  UNRESTRICTED,
  formatScope,
  scopeHeaders,
  parseScope,
  idsInScope,
  type Scope,
  type ScopeEntry,
} from '~/header';

const scope = (entries: [string, ScopeEntry][]): Scope => new Map(entries);

/**
 * The reason this file exists: the decision endpoint writes the header and
 * the guard reads it, so anything one produces the other must recover.
 */
test('every scope survives a round trip', () => {
  const cases = [
    scope([]),
    scope([['orders', { all: true, ids: [] }]]),
    scope([['orders', { all: false, ids: ['o7'] }]]),
    scope([['orders', { all: false, ids: ['o7', 'o11', 'o42'] }]]),
    scope([
      ['customers', { all: false, ids: ['acme', 'globex'] }],
      ['orders', { all: true, ids: [] }],
    ]),
  ];
  for (const original of cases) {
    assert.deepEqual(parseScope(scopeHeaders(original)), original, `round trip of ${formatScope(original)}`);
  }
});

test('an empty scope is the none sentinel, not an empty string', () => {
  assert.equal(formatScope(scope([])), NONE);
  assert.equal(parseScope({ 'x-scope': NONE }).size, 0);
});

test('renders the shapes the guard reads on the wire', () => {
  assert.equal(formatScope(scope([['orders', { all: true, ids: [] }]])), 'orders=*');
  assert.equal(formatScope(scope([['orders', { all: false, ids: ['o7', 'o11'] }]])), 'orders=o7,o11');
  assert.equal(
    formatScope(
      scope([
        ['customers', { all: false, ids: ['acme'] }],
        ['orders', { all: true, ids: [] }],
      ]),
    ),
    'customers=acme;orders=*',
  );
});

test('an unreadable header shows nothing rather than everything', () => {
  for (const raw of [undefined, '', 'garbage', '=o7', ';;;', NONE]) {
    assert.equal(idsInScope(parseScope({ 'x-scope': raw }), 'orders')?.length, 0, `for ${JSON.stringify(raw)}`);
  }
});

test('a type in the header but empty shows nothing', () => {
  assert.deepEqual(idsInScope(parseScope({ 'x-scope': 'orders=' }), 'orders'), []);
});

test('a wildcard is no restriction, an absent type is no rows', () => {
  assert.equal(idsInScope(parseScope({ 'x-scope': 'orders=*' }), 'orders'), undefined);
  assert.deepEqual(idsInScope(parseScope({ 'x-scope': 'customers=acme' }), 'orders'), []);
});

test('undefined ids and an empty list are not the same answer', () => {
  const unrestricted = idsInScope(parseScope({ 'x-scope': 'orders=*' }), 'orders');
  const nothing = idsInScope(parseScope({ 'x-scope': 'orders=' }), 'orders');
  assert.equal(unrestricted, undefined);
  assert.deepEqual(nothing, []);
  assert.notEqual(unrestricted, nothing);
});

test('a call with no scope at all raises rather than defaulting open', () => {
  for (const notAScope of [undefined, null, {}]) {
    assert.throws(() => idsInScope(notAScope as unknown as Scope, 'orders'), /must pass UNRESTRICTED/);
  }
});

test('a call with no gateway in its path says so by name', () => {
  assert.equal(idsInScope(UNRESTRICTED, 'orders'), undefined);
});

test('the sentinel survives duplicate copies of the package', () => {
  assert.equal(UNRESTRICTED, Symbol.for('@mojaloop/authz.INTERNAL'));
});

test('ids containing no separator survive', () => {
  const original = scope([['orders', { all: false, ids: ['a-b_c.d', 'UPPER'] }]]);
  assert.deepEqual(parseScope(scopeHeaders(original)), original);
});
