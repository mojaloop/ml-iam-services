import { messagesOf, ObjectRef } from '../../src/authzgen/problem';
import { Declared, DocumentSource, reconcile } from '../../src/operator/reconcile';
import { Reach } from '../../src/operator/routes';
import { fromResource } from '../../src/operator/sources';

const operation = (operationId: string, service: string, path: string, scopedBy?: string[]) => ({
  operationId,
  summary: `${operationId} on ${service}`,
  parameters: [...path.matchAll(/\{([^}]+)\}/g)].map((m) => ({
    name: m[1],
    in: 'path',
    required: true,
    schema: { type: 'string' },
  })),
  ...(scopedBy ? { 'x-authz': { scopedBy } } : {}),
  responses: { 200: { description: 'ok', content: { 'application/json': { schema: { type: 'object' } } } } },
});

const document = (service: string, paths: string[], scopedBy?: string[]) => {
  const bound = paths.flatMap((path) => {
    const parts = path.split('/').filter(Boolean);
    const at = parts.findIndex((s) => s.startsWith('{'));
    return at > 0 ? [parts[at - 1]!] : [];
  });
  const types = [...new Set([...(scopedBy ?? []), ...bound])];
  return {
    openapi: '3.1.0',
    info: { title: service, version: '1.0.0' },
    ...(types.length > 0 ? { 'x-authz': { resourceTypes: types } } : {}),
    servers: [{ url: '/' }],
    paths: Object.fromEntries(
      paths.map((path) => [path, { get: operation(`get${path.split('/')[1]}`, service, path, scopedBy) }]),
    ),
  };
};

const everything: Reach = { matches: [{ type: 'PathPrefix', path: '/' }] };

const declared = (
  service: string,
  paths: string[],
  options: {
    backend?: ObjectRef;
    source?: DocumentSource;
    hosts?: string[];
    reaches?: Reach[];
    exclude?: string[];
    scopedBy?: string[];
  } = {},
): Declared => {
  const backend = options.backend ?? { namespace: service, name: `${service}-api` };
  return {
    origin: `HTTPRoute/${service}/api → ${backend.namespace}/${backend.name}`,
    service,
    route: { namespace: service, name: 'api' },
    backend,
    source: options.source ?? { url: `http://${backend.name}.${backend.namespace}.svc/.authz/openapi` },
    document: document(service, paths, options.scopedBy),
    hosts: options.hosts ?? [`${service}.test`],
    reaches: options.reaches ?? [everything],
    exclude: options.exclude ?? [],
  };
};

const urlsOf = (rules: Array<{ match: { url: string } }> | undefined): string[] => (rules ?? []).map((r) => r.match.url);

const naming = (...members: Array<{ service: string; type: string }>) => ({
  resourceNames: Object.fromEntries(members.map((m) => [`${m.service}-${m.type}`, { label: m.type, members: [m] }])),
});

const widgets = naming({ service: 'alpha', type: 'widgets' });
const both = naming({ service: 'alpha', type: 'widgets' }, { service: 'beta', type: 'parts' });

describe('reconciling what the routes key', () => {
  it('composes every prefix into one deployment', () => {
    const result = reconcile(
      [declared('alpha', ['/widgets/{widgetId}']), declared('beta', ['/parts/{partId}'])],
      both,
    );
    expect(result.problems).toEqual([]);
    expect(result.held).toEqual([]);
    expect(result.composition?.catalog.map((c) => c.service)).toEqual(['alpha', 'beta']);
    expect(Object.keys(result.composition?.rules ?? {})).toEqual(['alpha', 'beta']);
  });

  it('tells the IAM its own callers, and no service', () => {
    const result = reconcile([declared('alpha', ['/widgets/{widgetId}']), declared('iam', ['/roles'])], widgets, undefined, 'iam');
    expect(result.problems).toEqual([]);
    const handlers = (service: string) =>
      result.services[service]!.rules.filter((r) => !r.id.endsWith('.preflight')).flatMap((r) => r.mutators.map((m) => m.handler));
    expect(handlers('iam')).toEqual(['header']);
    expect(handlers('alpha')).toEqual(['noop']);
  });

  it('combines the routes that send traffic to one backend under one prefix', () => {
    const result = reconcile(
      [
        declared('alpha', ['/widgets/{widgetId}', '/gadgets'], {
          reaches: [{ matches: [{ type: 'PathPrefix', path: '/widgets' }] }],
        }),
        declared('alpha', ['/widgets/{widgetId}', '/gadgets'], {
          reaches: [{ matches: [{ type: 'Exact', path: '/gadgets' }] }],
        }),
      ],
      widgets,
    );
    expect(result.problems).toEqual([]);
    expect(result.composition?.catalog[0]?.permissions.map((p) => p.id).sort()).toEqual([
      'alpha.getgadgets',
      'alpha.getwidgets',
    ]);
  });

  it('gives no permission to an operation no route sends', () => {
    const result = reconcile(
      [
        declared('alpha', ['/widgets/{widgetId}', '/gadgets'], {
          reaches: [{ matches: [{ type: 'PathPrefix', path: '/widgets' }] }],
        }),
      ],
      widgets,
    );
    expect(result.composition?.catalog[0]?.permissions.map((p) => p.id)).toEqual(['alpha.getwidgets']);
    expect(urlsOf(result.composition?.rules.alpha).some((url) => url.includes('gadgets'))).toBe(false);
  });

  /**
   * One host dispatching by path to several Services, each keyed on its own
   * prefix and reading the same whole-mount document.
   */
  it('confines a whole-mount operation to the paths the route sends its backend', () => {
    const mount = (service: string) => ({
      openapi: '3.1.0',
      info: { title: service, version: '1' },
      servers: [{ url: '/' }],
      paths: { '/': { get: operation('view', service, '/', []) } },
    });
    const behind = (service: string, prefixes: string[], exclude: string[]): Declared => ({
      ...declared(service, [], {
        backend: { namespace: 'mojaloop', name: service },
        hosts: ['intapi.test'],
        reaches: [{ matches: prefixes.map((path) => ({ type: 'PathPrefix' as const, path })) }],
        exclude,
      }),
      document: mount(service),
    });
    const result = reconcile([
      behind('lookup', ['/participants', '/parties'], ['/quotes']),
      behind('quotes', ['/quotes'], ['/participants', '/parties']),
    ]);
    expect(result.problems).toEqual([]);
    expect(result.composition?.catalog.map((c) => c.permissions.map((p) => p.id))).toEqual([
      ['lookup.view'],
      ['quotes.view'],
    ]);
    expect(urlsOf(result.composition?.rules.lookup)).toContain(
      '<http|https>://intapi.test<(?!/\\.authz/openapi(?:/|$)|/quotes(?:/|$))(?:/participants(?:/.*)?|/parties(?:/.*)?)>',
    );
    expect(urlsOf(result.composition?.rules.quotes)).toContain(
      '<http|https>://intapi.test<(?!/\\.authz/openapi(?:/|$)|/participants(?:/|$)|/parties(?:/|$))(?:/quotes(?:/.*)?)>',
    );
  });

  it('holds a prefix whose routes reach none of its operations', () => {
    const unreached = declared('alpha', ['/widgets/{widgetId}'], {
      reaches: [{ matches: [{ type: 'PathPrefix', path: '/elsewhere' }] }],
    });
    const result = reconcile([unreached], widgets);
    expect(result.held).toEqual(['alpha']);
    expect(messagesOf(result.problems)).toEqual([`${unreached.origin}: no operation of alpha's document is reached by its routes`]);
  });

  it('holds a prefix keyed on two Services, and publishes the rest', () => {
    const result = reconcile(
      [
        declared('alpha', ['/widgets/{widgetId}']),
        declared('alpha', ['/exports'], { backend: { namespace: 'acme', name: 'acme-exporter' } }),
        declared('beta', ['/parts/{partId}']),
      ],
      both,
    );
    expect(result.held).toEqual(['alpha']);
    expect(result.problems).toEqual([
      {
        message:
          'HTTPRoute/alpha/api → alpha/alpha-api, HTTPRoute/alpha/api → acme/acme-exporter: ' +
          'alpha is keyed on acme/acme-exporter and alpha/alpha-api; a prefix belongs to one Service',
        services: ['alpha'],
        routes: [{ namespace: 'alpha', name: 'api' }],
        documents: [],
      },
    ]);
    expect(result.composition?.catalog.map((c) => c.service)).toEqual(['beta']);
  });

  it('names the AuthzDocument a held prefix was read from, whatever the problem says', () => {
    const schema = { namespace: 'alpha', name: 'alpha-document' };
    const broken: Declared = {
      ...declared('alpha', [], { source: { schema } }),
      document: { openapi: '3.1.0', info: { title: 'a', version: '1' }, paths: { '/x': { get: { operationId: 'x' } } } },
    };
    const result = reconcile([broken], widgets);
    expect(result.held).toEqual(['alpha']);
    expect(result.problems).toEqual([
      {
        message: `${broken.origin}: GET /x: summary is required for the catalog`,
        services: ['alpha'],
        routes: [{ namespace: 'alpha', name: 'api' }],
        documents: [schema],
      },
    ]);
  });

  it('keeps a held prefix at what it last composed to', () => {
    const before = reconcile(
      [declared('alpha', ['/widgets/{widgetId}']), declared('beta', ['/parts/{partId}'])],
      both,
    );
    const unread: Declared = { ...declared('alpha', []), document: undefined, problem: 'answered 503' };
    const after = reconcile([unread, declared('beta', ['/parts/{partId}'])], both, { services: before.services });
    expect(after.held).toEqual(['alpha']);
    expect(messagesOf(after.problems)).toEqual([`${unread.origin}: answered 503`]);
    expect(after.composition?.catalog).toEqual(before.composition?.catalog);
  });

  it('leaves out a prefix that never composed', () => {
    const broken: Declared = {
      ...declared('broken', []),
      document: { openapi: '3.1.0', info: { title: 'b', version: '1' }, paths: { '/x': { get: { operationId: 'x' } } } },
    };
    const result = reconcile([declared('alpha', ['/widgets/{widgetId}']), broken], widgets);
    expect(result.held).toEqual(['broken']);
    expect(messagesOf(result.problems)).toEqual([`${broken.origin}: GET /x: summary is required for the catalog`]);
    expect(result.composition?.catalog.map((c) => c.service)).toEqual(['alpha']);
  });

  it('holds a prefix read from two documents', () => {
    const result = reconcile(
      [
        declared('alpha', ['/widgets/{widgetId}']),
        declared('alpha', ['/widgets/{widgetId}'], { source: { schema: { namespace: 'alpha', name: 'other' } } }),
      ],
      widgets,
    );
    expect(result.held).toEqual(['alpha']);
    expect(result.problems).toEqual([
      {
        message:
          'HTTPRoute/alpha/api → alpha/alpha-api: ' +
          'alpha is read from AuthzDocument/alpha/other and http://alpha-api.alpha.svc/.authz/openapi; a prefix has one document',
        services: ['alpha'],
        routes: [{ namespace: 'alpha', name: 'api' }],
        documents: [{ namespace: 'alpha', name: 'other' }],
      },
    ]);
  });

  it('holds a prefix its routes send different paths on different hosts', () => {
    const result = reconcile(
      [
        declared('alpha', ['/widgets/{widgetId}'], { hosts: ['a.test'] }),
        declared('alpha', ['/widgets/{widgetId}'], {
          hosts: ['b.test'],
          reaches: [{ matches: [{ type: 'PathPrefix', path: '/widgets' }] }],
        }),
      ],
      widgets,
    );
    expect(result.held).toEqual(['alpha']);
    expect(messagesOf(result.problems)).toEqual([
      'HTTPRoute/alpha/api → alpha/alpha-api: alpha is reached through different paths on a.test and b.test',
    ]);
  });

  it('composes a prefix every host of which is sent the same paths', () => {
    const result = reconcile(
      [
        declared('alpha', ['/widgets/{widgetId}'], { hosts: ['a.test'] }),
        declared('alpha', ['/widgets/{widgetId}'], { hosts: ['b.test'] }),
      ],
      widgets,
    );
    expect(result.problems).toEqual([]);
    expect(urlsOf(result.composition?.rules.alpha).some((url) => url.includes('<http|https>://<a\\.test|b\\.test>/widgets/'))).toBe(true);
  });

  it('holds a prefix its routes rewrite differently', () => {
    const result = reconcile(
      [
        declared('alpha', ['/widgets/{widgetId}'], {
          reaches: [{ matches: [{ type: 'PathPrefix', path: '/a' }], rewrite: { from: '/a', to: '' } }],
        }),
        declared('alpha', ['/widgets/{widgetId}'], {
          reaches: [{ matches: [{ type: 'PathPrefix', path: '/b' }], rewrite: { from: '/b', to: '' } }],
        }),
      ],
      widgets,
    );
    expect(result.held).toEqual(['alpha']);
    expect(messagesOf(result.problems)).toEqual([
      'HTTPRoute/alpha/api → alpha/alpha-api: alpha is reached through different rewrites (/a→, /b→)',
    ]);
  });

  it('publishes nothing when two prefixes answer the same request', () => {
    const result = reconcile(
      [
        declared('alpha', ['/widgets/{widgetId}'], { hosts: ['shared.test'] }),
        declared('beta', ['/widgets/{widgetId}'], { hosts: ['shared.test'] }),
      ],
      naming({ service: 'alpha', type: 'widgets' }, { service: 'beta', type: 'widgets' }),
    );
    expect(result.composition).toBeUndefined();
    expect(result.problems).toContainEqual(expect.objectContaining({ services: ['beta', 'alpha'] }));
    expect(messagesOf(result.problems).join(' ')).toMatch(/beta and alpha both match/);
  });

  it('asks the deployment to vouch for a type no path binds', () => {
    const unrouted = [declared('alpha', ['/widgets'], { scopedBy: ['participants'] })];
    expect(reconcile(unrouted).held).toEqual(['alpha']);
    expect(
      reconcile(unrouted, {
        resourceNames: {
          Participant: { label: 'Participant', members: [{ service: 'alpha', type: 'participants' }] },
        },
      }).problems,
    ).toEqual([]);
  });

  it('composes a document that dropped an operation the last composition had', () => {
    const before = reconcile([declared('alpha', ['/widgets/{widgetId}'])], widgets);
    const gadgets = naming({ service: 'alpha', type: 'gadgets' });
    const after = reconcile([declared('alpha', ['/gadgets/{gadgetId}'])], gadgets, { services: before.services });
    expect(after.problems).toEqual([]);
    expect(after.composition?.catalog[0]?.permissions.map((p) => p.id)).toEqual(['alpha.getgadgets']);
  });
});

describe('an AuthzDocument', () => {
  const resource = (spec: Record<string, unknown>) => ({ metadata: { name: 'reports', namespace: 'acme' }, spec });

  it('carries its document as an object, read like a served one', async () => {
    const read = await fromResource(resource({ document: document('reports', ['/reports/{reportName}']) }));
    const result = reconcile(
      [{ ...declared('reports', []), document: read }],
      naming({ service: 'reports', type: 'reports' }),
    );
    expect(result.composition?.catalog[0]?.permissions.map((p) => p.id)).toEqual(['reports.getreports']);
  });

  it('refuses one carrying no document', async () => {
    await expect(fromResource(resource({}))).rejects.toThrow(
      'AuthzDocument/acme/reports: spec.document is not an OpenAPI document',
    );
  });

  it('refuses a document older than OpenAPI 3.1', async () => {
    const old = { ...document('reports', ['/reports/{reportName}']), openapi: '3.0.3' };
    await expect(fromResource(resource({ document: old }))).rejects.toThrow(
      'AuthzDocument/acme/reports: OpenAPI 3.0 is not supported; the document must declare 3.1 or later',
    );
  });
});
