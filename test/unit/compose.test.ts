import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { compose, ComposedService, diffCatalogs, ungated } from '../../src/authzgen/compose';
import { derive } from '../../src/authzgen/derive';
import { CANONICAL_STUBS } from '../../src/authzgen/emit-model';
import { ketoNamespace } from '../../src/authzgen/keto-name';
import { CatalogPermission, ServiceBundle, ServiceCatalog } from '../../src/authzgen/types';
import { indexCatalogs } from '../../src/iam/roles';
import { readCatalogs } from '../../src/iam/server';

const permission = (id: string, scopedBy: string[] = [], bound: string[] = []): CatalogPermission => ({
  id,
  relation: id.split('.').slice(1).join('.'),
  operationId: id.split('.').slice(1).join('.'),
  summary: id,
  deprecated: false,
  method: 'GET',
  path: '/x',
  scopedBy,
  bound,
});

const catalog = (service: string, permissions: CatalogPermission[]): ServiceCatalog => ({
  service,
  namespace: service,
  title: service,
  basePath: '',
  resourceTypes: [...new Set(permissions.flatMap((p) => p.scopedBy))].sort(),
  permissions,
});

const bundle = (service: string, permissions: CatalogPermission[]): ServiceBundle => ({
  service,
  title: service,
  basePath: '',
  resourceTypes: [...new Set(permissions.flatMap((p) => p.scopedBy))].sort(),
  permissions: permissions.map((p) => ({
    id: p.id,
    name: p.relation,
    operationId: p.relation,
    method: p.method,
    path: p.path,
    summary: p.summary,
    deprecated: false,
    anonymous: false,
    security: ['apiKey:cookie'],
    scopedBy: p.scopedBy.map((type) =>
      p.bound.includes(type) ? { type, param: `${type}Id`, captureIndex: 1 } : { type },
    ),
  })),
});

const service = (name: string, permissions: CatalogPermission[], rules = ''): ComposedService => ({
  bundle: bundle(name, permissions),
  rules,
  catalog: catalog(name, permissions),
  derivation: `# ${name}\n`,
});

const rulesFor = (id: string, url: string, method = 'GET') =>
  `- id: ${id}\n  match:\n    url: ${url}\n    methods:\n      - ${method}\n`;

describe('composing a deployment', () => {
  it('stages the shared classes once and one namespace per service, in a stable order', () => {
    const { model } = compose([service('widgets', [permission('widgets.get')]), service('alpha', [permission('alpha.get')])]);
    expect(model.split('export class User').length - 1).toBe(1);
    expect(model.indexOf('class alpha')).toBeLessThan(model.indexOf('class widgets'));
    expect(model.startsWith(CANONICAL_STUBS)).toBe(true);
  });

  it('refuses two services claiming one permission id', () => {
    const { problems } = compose([
      service('alpha', [permission('shared.get')]),
      service('beta', [permission('shared.get')]),
    ]);
    expect(problems).toEqual(['permission shared.get is claimed by alpha and beta']);
  });

  it('refuses two services claiming one request', () => {
    const url = '<http|https>://portal.test/api/x<$>';
    const { problems } = compose([
      service('alpha', [permission('alpha.get')], rulesFor('alpha.get', url)),
      service('beta', [permission('beta.get')], rulesFor('beta.get', url)),
    ]);
    expect(problems).toEqual([`beta and alpha both match GET ${url}`]);
  });

  it('lets two services serve the same path on different hosts', () => {
    const { problems } = compose([
      service('alpha', [permission('alpha.get')], rulesFor('alpha.get', '<http|https>://a.test/api/x<$>')),
      service('beta', [permission('beta.get')], rulesFor('beta.get', '<http|https>://b.test/api/x<$>')),
    ]);
    expect(problems).toEqual([]);
  });

  it('refuses one service registered twice', () => {
    const { problems } = compose([service('alpha', [permission('alpha.get')]), service('alpha', [permission('alpha.list')])]);
    expect(problems).toEqual(['service alpha is registered 2 times']);
  });

  /**
   * The vocabulary is total: every type a service is about is picked and
   * labelled by the noun that names it, bound or not.
   */
  it('asks the deployment to name every type a service is about', () => {
    const rows = [service('reports', [permission('reports.getRow', ['participants'])])];
    expect(compose(rows).problems).toEqual([
      'reports is about participants, and no resource name lists reports.participants',
    ]);
    const bound = [service('mcm', [permission('mcm.getDfsp', ['dfsps'], ['dfsps'])])];
    expect(compose(bound).problems).toEqual(['mcm is about dfsps, and no resource name lists mcm.dfsps']);
    expect(
      compose(rows, {
        resourceNames: {
          Participant: { label: 'Participant', members: [{ service: 'reports', type: 'participants' }] },
        },
      }).problems,
    ).toEqual([]);
  });

  /**
   * The other direction. A resource name asserts something about a service's
   * vocabulary, and an assertion nobody checks lets an operator pick a
   * resource whose grant binds nothing.
   */
  it('refuses a resource name for a type its service is not about', () => {
    const rows = [service('reports', [permission('reports.getRow', ['participants'])])];
    expect(
      compose(rows, {
        resourceNames: {
          Participant: { label: 'Participant', members: [{ service: 'reports', type: 'partcipants' }] },
        },
      }).problems,
    ).toEqual([
      'reports is about participants, and no resource name lists reports.participants',
      'resource name Participant lists reports.partcipants, which reports is not about',
    ]);
  });

  /**
   * A deployment names its vocabulary once, for every service it may run; one
   * not running, or held, binds nothing and stops nothing else.
   */
  it('reports a resource name member whose service is not composed, and composes the rest', () => {
    const rows = [service('reports', [permission('reports.getRow', ['participants'])])];
    const composition = compose(rows, {
      resourceNames: {
        Participant: {
          label: 'Participant',
          members: [
            { service: 'reports', type: 'participants' },
            { service: 'ledger', type: 'participants' },
          ],
        },
      },
    });
    expect(composition.problems).toEqual([]);
    expect(composition.unbound).toEqual(['resource name Participant lists ledger, which this deployment does not compose']);
  });

  it('keeps a prefix that is an identifier as its Keto namespace, and encodes any other', () => {
    expect(ketoNamespace('portalShell')).toBe('portalShell');
    expect(ketoNamespace('portal-shell')).toBe('portal_2d_shell');
    expect(ketoNamespace('2fa')).toBe('_2fa');
  });

  it('refuses two prefixes meeting on one Keto namespace', () => {
    const { problems } = compose([
      service('portal-shell', [permission('portal-shell.get')]),
      service('portal_2d_shell', [permission('portal_2d_shell.get')]),
    ]);
    expect(problems).toContain('portal-shell and portal_2d_shell are both Keto namespace portal_2d_shell');
  });

  it('refuses a prefix a permission id cannot carry', () => {
    const doc = { paths: { '/x': { get: { operationId: 'get', summary: 'x', security: [] } } } };
    expect(() => derive(doc, 'portal.shell')).toThrow(/is not a permission prefix/);
    expect(() => derive(doc, 'portal-shell')).not.toThrow();
  });
});

describe('the diff gate', () => {
  const before = [catalog('mcm', [permission('mcm.a', ['dfsps'], ['dfsps']), permission('mcm.b')])];

  it('sees an addition, which nobody holds yet', () => {
    const after = [catalog('mcm', [...before[0]!.permissions, permission('mcm.c')])];
    const diff = diffCatalogs(before, after);
    expect(diff).toEqual({ added: ['mcm.c'], removed: [], changed: [] });
    expect(ungated(diff)).toEqual([]);
  });

  it('sees a removal, which orphans every grant on it', () => {
    const after = [catalog('mcm', [permission('mcm.a', ['dfsps'], ['dfsps'])])];
    const diff = diffCatalogs(before, after);
    expect(diff.removed).toEqual(['mcm.b']);
    expect(ungated(diff)).toEqual(['mcm.b is gone and no migration says where its grants go']);
    expect(ungated(diff, { 'mcm.b': null })).toEqual([]);
  });

  it('sees a permission whose stored tuples would stop answering', () => {
    const after = [catalog('mcm', [permission('mcm.a', ['dfsps'], []), permission('mcm.b')])];
    const diff = diffCatalogs(before, after);
    expect(diff.changed).toEqual([{ id: 'mcm.a', was: 'a over [dfsps]', now: 'a over []' }]);
    expect(ungated(diff)).toHaveLength(1);
    expect(ungated(diff, { 'mcm.a': 'mcm.a' })).toEqual([]);
  });
});

describe('a declared source', () => {
  const withSource = (overrides: Record<string, unknown>) => ({
    resourceNames: {
      Participant: {
        members: [{ service: 'ledger', type: 'participants' }],
        source: { url: 'http://central-ledger:3001/participants', id: '/name', ...overrides },
      },
    },
  });
  const ledger = service('ledger', [permission('ledger.get', ['participants'], [])]);

  it('accepts a url with the id pointer, list defaulting to the body', () => {
    expect(compose([ledger], withSource({})).problems).toEqual([]);
  });

  it('refuses a url that is not one', () => {
    const { problems } = compose([ledger], withSource({ url: 'central-ledger:3001' }));
    expect(problems.join('\n')).toContain('source.url "central-ledger:3001" is not an http(s) URL');
  });

  it('refuses a pointer that is not one', () => {
    const { problems } = compose([ledger], withSource({ id: 'name' }));
    expect(problems.join('\n')).toContain('source.id "name" is not a JSON Pointer');
  });
});

describe('what the aggregator writes and the IAM reads', () => {
  it('offers every service of the composition by permission id', () => {
    const composition = compose([
      service('mcm', [permission('mcm.a'), permission('mcm.b')]),
      service('reports', [permission('reports.get')]),
    ]);
    const file = join(mkdtempSync(join(tmpdir(), 'catalog-')), 'catalog.json');
    writeFileSync(file, `${JSON.stringify(composition.catalog, null, 2)}\n`);

    const index = indexCatalogs(readCatalogs([file]));
    expect([...index.keys()].sort()).toEqual(['mcm.a', 'mcm.b', 'reports.get']);
  });
});
