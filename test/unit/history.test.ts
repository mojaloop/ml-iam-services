import { CatalogPermission, ServiceCatalog } from '../../src/authzgen/types';
import { advance, EMPTY, History } from '../../src/iam/history';

const permission = (id: string, method: string, path: string, replaces?: string[]): CatalogPermission => ({
  id,
  relation: id.split('.')[1]!,
  operationId: id.split('.')[1]!,
  summary: id,
  deprecated: false,
  method,
  path,
  scopedBy: [],
  bound: [],
  resourceNames: {},
  ...(replaces !== undefined ? { replaces } : {}),
});

const catalog = (service: string, permissions: CatalogPermission[]): ServiceCatalog => ({
  service,
  namespace: service,
  title: service,
  basePath: '',
  resourceTypes: [],
  permissions,
});

const before = advance(EMPTY, [
  catalog('ledger', [
    permission('ledger.getEntry', 'GET', '/entries/{id}'),
    permission('ledger.purge', 'DELETE', '/entries'),
    permission('ledger.listEntries', 'GET', '/entries'),
  ]),
  catalog('reports', [permission('reports.run', 'POST', '/run')]),
]);

describe('what became of a permission a service no longer offers', () => {
  it('is renamed when another of the service answers the same method and path', () => {
    const after = advance(before, [
      catalog('ledger', [permission('ledger.fetchEntry', 'GET', '/entries/{entry}'), permission('ledger.listEntries', 'GET', '/entries')]),
      catalog('reports', [permission('reports.run', 'POST', '/run')]),
    ]);
    expect(after.renamed).toEqual({ 'ledger.getEntry': 'ledger.fetchEntry' });
    expect(after.removed).toEqual(['ledger.purge']);
  });

  it('is renamed to the one declaring it replaces it, wherever its path went', () => {
    const after = advance(before, [
      catalog('ledger', [
        permission('ledger.readEntry', 'GET', '/v2/entry/{id}', ['ledger.getEntry']),
        permission('ledger.listEntries', 'GET', '/entries'),
      ]),
      catalog('reports', [permission('reports.run', 'POST', '/run')]),
    ]);
    expect(after.renamed['ledger.getEntry']).toBe('ledger.readEntry');
  });

  it('is not claimed by a permission that was already there', () => {
    const after = advance(before, [
      catalog('ledger', [permission('ledger.listEntries', 'GET', '/entries/{id}')]),
      catalog('reports', [permission('reports.run', 'POST', '/run')]),
    ]);
    expect(after.renamed).toEqual({});
    expect(after.removed).toEqual(['ledger.getEntry', 'ledger.purge']);
  });

  it('is decided nothing about while its service is not composed', () => {
    const after = advance(before, [catalog('ledger', [permission('ledger.getEntry', 'GET', '/entries/{id}'), permission('ledger.purge', 'DELETE', '/entries'), permission('ledger.listEntries', 'GET', '/entries')])]);
    expect(after.removed).toEqual([]);
    expect(after.known['reports.run']).toBeDefined();
  });

  it('follows renames across compositions to the name that is current', () => {
    const once: History = advance(before, [
      catalog('ledger', [permission('ledger.fetchEntry', 'GET', '/entries/{id}'), permission('ledger.listEntries', 'GET', '/entries')]),
      catalog('reports', [permission('reports.run', 'POST', '/run')]),
    ]);
    const twice = advance(once, [
      catalog('ledger', [permission('ledger.readEntry', 'GET', '/entries/{id}'), permission('ledger.listEntries', 'GET', '/entries')]),
      catalog('reports', [permission('reports.run', 'POST', '/run')]),
    ]);
    expect(twice.renamed).toMatchObject({ 'ledger.getEntry': 'ledger.readEntry', 'ledger.fetchEntry': 'ledger.readEntry' });
  });

  it('is forgotten as renamed or removed once it comes back', () => {
    const gone = advance(before, [
      catalog('ledger', [permission('ledger.listEntries', 'GET', '/entries')]),
      catalog('reports', [permission('reports.run', 'POST', '/run')]),
    ]);
    const back = advance(gone, [
      catalog('ledger', [permission('ledger.purge', 'DELETE', '/entries'), permission('ledger.listEntries', 'GET', '/entries')]),
      catalog('reports', [permission('reports.run', 'POST', '/run')]),
    ]);
    expect(back.removed).toEqual(['ledger.getEntry']);
  });
});
