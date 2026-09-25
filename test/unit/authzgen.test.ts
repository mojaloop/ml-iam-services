import { DocumentError } from '@mojaloop/authz/document';

import { derive } from '../../src/authzgen/derive';
import { emitModel } from '../../src/authzgen/emit-model';
import { emitRules } from '../../src/authzgen/emit-rules';

/* eslint-disable @typescript-eslint/no-explicit-any */

const schemes = {
  session: { type: 'apiKey', in: 'cookie', name: 'session' },
  machineToken: { type: 'http', scheme: 'bearer' },
};

const op = (operationId: string, extra: Record<string, unknown> = {}) => ({
  operationId,
  summary: `does ${operationId}`,
  security: [{ session: [] }],
  ...extra,
});

/** The types a fixture's paths use, the way derive counts them. */
const typesOf = (paths: Record<string, unknown>): string[] => {
  const types = new Set<string>();
  for (const [path, item] of Object.entries(paths)) {
    const parts = path.split('/').filter(Boolean);
    const outermost = parts.findIndex((s) => s.startsWith('{'));
    const bound = outermost > 0 && !parts[outermost - 1]!.startsWith('{') ? parts[outermost - 1]! : undefined;
    for (const node of Object.values(item as Record<string, any>)) {
      const scopedBy = node?.['x-authz']?.scopedBy;
      if (scopedBy === undefined) {
        if (bound !== undefined) types.add(bound);
      } else {
        for (const entry of scopedBy) types.add(typeof entry === 'string' ? entry : Object.keys(entry)[0]!);
      }
    }
  }
  return [...types].sort();
};

/** The namespace the route is annotated with, which every fixture derives under. */
const SERVICE = 'example';

const spec = (paths: Record<string, unknown>, resourceTypes: string[] = typesOf(paths)) => ({
  openapi: '3.0.1',
  info: { title: 'Example API' },
  servers: [{ url: '/api' }],
  ...(resourceTypes.length > 0 ? { 'x-authz': { resourceTypes } } : {}),
  components: { securitySchemes: schemes },
  paths,
});

const permissionOf = (doc: any, id: string) => {
  const found = derive(doc, SERVICE).permissions.find((p) => p.id === id);
  if (!found) throw new Error(`no permission ${id}`);
  return found;
};

describe('authzgen derivation', () => {
  it('derives the resource type from the outermost path parameter', () => {
    const doc = spec({ '/widgets/{widgetId}/parts': { get: op('getWidgetParts') } });
    const p = permissionOf(doc, 'example.getWidgetParts');
    expect(p.scopedBy).toEqual([{ param: 'widgetId', type: 'widgets', captureIndex: 1 }]);
  });

  it('treats deeper parameters as business data', () => {
    const doc = spec({ '/widgets/{widgetId}/parts/{partId}/fit': { post: op('fitPart') } });
    expect(permissionOf(doc, 'example.fitPart').scopedBy.map((r) => r.type)).toEqual(['widgets']);
  });

  it('declares a type the path binds no id for', () => {
    const doc = spec({
      '/widgets': { get: op('getWidgets', { 'x-authz': { scopedBy: ['widgets'] } }) },
      '/widgets/{widgetId}': { get: op('getWidget') },
    });
    expect(permissionOf(doc, 'example.getWidgets').scopedBy).toEqual([{ type: 'widgets' }]);
  });

  it('orders bound types by capture index and puts unbound types last', () => {
    const doc = spec({
      '/reports/{reportId}/widgets/{widgetId}': {
        get: op('getReportRows', { 'x-authz': { scopedBy: ['parts', { widgets: 'widgetId' }, { reports: 'reportId' }] } }),
      },
      '/parts/{partId}': { get: op('getPart') },
    });
    expect(permissionOf(doc, 'example.getReportRows').scopedBy).toEqual([
      { param: 'reportId', type: 'reports', captureIndex: 1 },
      { param: 'widgetId', type: 'widgets', captureIndex: 2 },
      { type: 'parts' },
    ]);
  });

  it('names a permission after the route and the operation', () => {
    const doc = spec({ '/widgets/{widgetId}/keys': { post: op('postWidgetKeys') } });
    const p = permissionOf(doc, 'example.postWidgetKeys');
    expect(p.name).toBe('postWidgetKeys');
    expect(p.operationId).toBe('postWidgetKeys');
  });

  it('supports an empty resource list where the outer id is reference data', () => {
    const doc = spec({
      '/regions/{regionId}/widgets': { get: op('getWidgetsByRegion', { 'x-authz': { scopedBy: [] } }) },
      '/widgets/{widgetId}': { get: op('getWidget') },
    });
    expect(permissionOf(doc, 'example.getWidgetsByRegion').scopedBy).toEqual([]);
    expect(derive(doc, SERVICE).resourceTypes).toEqual(['widgets']);
  });

  it('counts every parameter towards the capture index, bound or not', () => {
    const doc = spec({
      '/{tenant}/widgets/{widgetId}': { get: op('getTenantWidget', { 'x-authz': { scopedBy: [{ widgets: 'widgetId' }] } }) },
    });
    expect(permissionOf(doc, 'example.getTenantWidget').scopedBy).toEqual([
      { param: 'widgetId', type: 'widgets', captureIndex: 2 },
    ]);
  });

  it('leaves a document nothing to say about how a caller proves who they are', () => {
    const doc = spec({ '/widgets/{widgetId}': { get: op('getWidget', { security: [] }) } });
    expect(Object.keys(permissionOf(doc, 'example.getWidget'))).not.toContain('security');
  });

  describe('rejections', () => {
    const rejects = (doc: unknown, message: RegExp) => {
      expect(() => derive(doc, SERVICE)).toThrow(DocumentError);
      expect(() => derive(doc, SERVICE)).toThrow(message);
    };

    it('requires the service to be a prefix a permission id can carry', () => {
      const doc = spec({ '/widgets': { get: op('getWidgets', { 'x-authz': { scopedBy: [] } }) } });
      expect(() => derive(doc, 'portal.shell')).toThrow(/is not a permission prefix/);
    });

    it('writes an encoded prefix as the namespace in the model and the check', () => {
      const doc = spec({ '/widgets': { get: op('getWidgets', { 'x-authz': { scopedBy: [] } }) } });
      const bundle = derive(doc, 'portal-shell');
      expect(emitModel(bundle)).toContain('export class portal_2d_shell implements Namespace {}');
      expect((emitRules(bundle) as any[])[1].authorizer.config.payload).toContain('"namespace":"portal_2d_shell"');
      expect(bundle.permissions[0]!.id).toBe('portal-shell.getWidgets');
    });

    it('requires a summary for the catalog', () => {
      rejects(spec({ '/widgets': { get: { operationId: 'getWidgets', security: [] } } }), /summary is required/);
    });

    it('rejects unknown x-authz keys', () => {
      const doc = spec({ '/widgets': { get: op('getWidgets', { 'x-authz': { scope: 'widgets' } }) } });
      rejects(doc, /unknown x-authz key "scope"/);
    });

    it('accepts a type the document serves no route for', () => {
      // A service can return rows about a resource it never routes; whether
      // the name is one the deployment knows is not decidable from here
      const doc = spec({
        '/widgets': { get: op('getWidgets', { 'x-authz': { scopedBy: ['gadgets'] } }) },
      });
      expect(permissionOf(doc, 'example.getWidgets').scopedBy).toEqual([{ type: 'gadgets' }]);
    });

    it('rejects a resource type listed twice', () => {
      const doc = spec({
        '/widgets': { get: op('getWidgets', { 'x-authz': { scopedBy: ['widgets', 'widgets'] } }) },
      });
      rejects(doc, /lists "widgets" twice/);
    });

    it('rejects a bare entry for a type the path binds', () => {
      const doc = spec({
        '/widgets/{widgetId}': { get: op('getWidget', { 'x-authz': { scopedBy: ['widgets'] } }) },
      });
      rejects(doc, /the path binds widgets through \{widgetId\}; write `widgets: widgetId`/);
    });

    it('rejects a binding to a parameter the path does not have', () => {
      const doc = spec({
        '/widgets/{widgetId}': { get: op('getWidget', { 'x-authz': { scopedBy: [{ widgets: 'widgetName' }] } }) },
      });
      rejects(doc, /binds widgets to \{widgetName\}, which is not a parameter of this path/);
    });

    it('rejects a typed document that declares no resourceTypes', () => {
      const doc = spec({ '/widgets/{widgetId}': { get: op('getWidget') } }, []);
      rejects(doc, /the document is about \[widgets\]; declare them in x-authz.resourceTypes/);
    });

    it('rejects an operation using a type outside the declared list', () => {
      const doc = spec({ '/widgets/{widgetId}': { get: op('getWidget') } }, ['gadgets']);
      rejects(doc, /operations use resource type "widgets", which x-authz.resourceTypes does not declare/);
    });

    it('rejects a declared type no operation uses', () => {
      const doc = spec({ '/widgets/{widgetId}': { get: op('getWidget') } }, ['widgets', 'reports']);
      rejects(doc, /x-authz.resourceTypes declares "reports", which no operation uses/);
    });

    it('rejects an unknown x-authz key at the root', () => {
      const doc = { ...spec({ '/health': { get: op('getHealth', { security: [] }) } }) } as any;
      doc['x-authz'] = { scopes: [] };
      rejects(doc, /the document root: unknown x-authz key "scopes"/);
    });

    const listOf = (items: unknown) => ({
      responses: { 200: { content: { 'application/json': { schema: { type: 'array', items } } } } },
    });

    it('rejects a collection GET that binds no id and declares no types', () => {
      const doc = spec({ '/widgets': { get: op('getWidgets', listOf({ type: 'object' })) } });
      rejects(doc, /returns a list and binds no resource id/);
    });

    it.each([
      ['it names the row type', { 'x-authz': { scopedBy: ['widgets'] } }],
      ['it declares the rows unscoped', { 'x-authz': { scopedBy: [] } }],
    ])('accepts a collection GET when %s', (_label, extra) => {
      const doc = spec({
        '/widgets': { get: op('getWidgets', { ...listOf({ type: 'object' }), ...extra }) },
        '/widgets/{widgetId}': { get: op('getWidget') },
      });
      expect(() => derive(doc, SERVICE)).not.toThrow();
    });

    it('does not ask a collection GET under a bound resource to declare anything', () => {
      const doc = spec({
        '/widgets/{widgetId}/parts': { get: op('getWidgetParts', listOf({ type: 'object' })) },
      });
      expect(permissionOf(doc, 'example.getWidgetParts').scopedBy).toEqual([
        { param: 'widgetId', type: 'widgets', captureIndex: 1 },
      ]);
    });

    it('rejects duplicate permission ids', () => {
      const doc = spec({
        '/a': { get: op('same') },
        '/b': { get: op('same') },
      });
      rejects(doc, /duplicate permission id/);
    });
  });
});

describe('authzgen rule emission', () => {
  const doc = spec({
    '/widgets': {
      get: op('getWidgets', { 'x-authz': { scopedBy: ['widgets'] } }),
      post: op('createWidget'),
    },
    '/widgets/summary': { get: op('getWidgetSummary') },
    '/widgets/{widgetId}': { get: op('getWidget') },
    '/health': { get: op('getHealth', { security: [] }) },
  });
  // What composition stamps on every scoped type before rules emit
  const named = (bundle: ReturnType<typeof derive>) => {
    for (const p of bundle.permissions) for (const a of p.scopedBy) a.resourceName = 'Widget';
    return bundle;
  };
  const rules = emitRules(named(derive(doc, SERVICE))) as any[];
  const byIdIn = (list: any[], id: string) => list.find((r) => r.id === id);
  const byId = (id: string) => byIdIn(rules, id);

  it('emits one rule per operation plus a preflight', () => {
    expect(rules).toHaveLength(6);
    expect(byId('example.preflight').match.methods).toEqual(['OPTIONS']);
  });

  it('excludes competing literal siblings from a templated segment', () => {
    expect(byId('example.getWidget').match.url).toBe(
      '<http|https>://{host}{path}/api/widgets/<?!summary><(?<widgetId>[^/]+)><$>',
    );
  });

  it('prefixes the server base path and anchors the match', () => {
    expect(byId('example.getWidgets').match.url).toBe('<http|https>://{host}{path}/api/widgets<$>');
  });

  it('answers at the root of a host the deployment named but gave no mount path', () => {
    const served = emitRules(derive(doc, SERVICE), { hosts: ['api.example.test'] }) as any[];
    for (const rule of served) expect(rule.match.url).not.toContain('{');
    expect(byIdIn(served, 'example.getWidgets').match.url).toBe('<http|https>://api.example.test/api/widgets<$>');
  });

  it('mounts under the prefix a route rewrites away', () => {
    const served = emitRules(derive(doc, SERVICE), {
      hosts: ['portal.example.test'],
      rewrite: { from: '/widgets/', to: '' },
    }) as any[];
    expect(byIdIn(served, 'example.getWidgets').match.url).toBe(
      '<http|https>://portal.example.test/widgets/api/widgets<$>',
    );
  });

  it('maps a rewrite onto the base path back to the path clients send', () => {
    const served = emitRules(derive(doc, SERVICE), {
      hosts: ['portal.example.test'],
      rewrite: { from: '/w', to: '/api' },
    }) as any[];
    expect(byIdIn(served, 'example.getWidgets').match.url).toBe('<http|https>://portal.example.test/w/widgets<$>');
  });

  it('refuses a rewrite that never reaches the base path', () => {
    expect(() =>
      emitRules(derive(doc, SERVICE), { hosts: ['portal.example.test'], rewrite: { from: '/w', to: '/v2' } }),
    ).toThrow(/rewrites \/w to \/v2, which never reaches \/api/);
  });

  it('answers on every host a route names, wildcards one label deep', () => {
    const served = emitRules(derive(doc, SERVICE), { hosts: ['b.example.test', '*.example.org'] }) as any[];
    expect(byIdIn(served, 'example.getWidgets').match.url).toBe(
      '<http|https>://<[^.]+\\.example\\.org|b\\.example\\.test>/api/widgets<$>',
    );
  });

  it('gives an operation at the root the whole mount, an application its own routes resolve within', () => {
    const app = {
      openapi: '3.0.1',
      info: { title: 'Example App' },
      servers: [{ url: '/' }],
      components: { securitySchemes: schemes },
      paths: { '/': { get: op('viewApp', { 'x-authz': { scopedBy: [] } }) } },
    };
    const served = emitRules(derive(app, 'exampleApp'), { hosts: ['app.example.test'] }) as any[];
    expect(byIdIn(served, 'exampleApp.viewApp').match.url).toBe(
      '<http|https>://app.example.test<(?!/\\.authz/openapi(?:/|$))(?:/.*)?>',
    );

    const beside = emitRules(derive(app, 'exampleApp'), {
      hosts: ['app.example.test'],
      exclude: ['/api/', '/reports'],
    }) as any[];
    expect(byIdIn(beside, 'exampleApp.viewApp').match.url).toBe(
      '<http|https>://app.example.test<(?!/\\.authz/openapi(?:/|$)|/api(?:/|$)|/reports(?:/|$))(?:/.*)?>',
    );
  });

  it('addresses the service namespace with a resource-name-qualified object', () => {
    expect(byId('example.getWidget').authorizer.config.payload).toContain(
      '"namespace":"example","object":"Widget/{{ printIndex .MatchContext.RegexpCaptureGroups 1 }}"',
    );
  });

  it('asks for every declared type in scope, bound or not, under both spellings', () => {
    expect(byId('example.getWidgets').authorizer.config.payload).toContain(
      '"scope":[{"type":"widgets","resourceName":"Widget"}]',
    );
    expect(byId('example.getWidget').authorizer.config.payload).toContain(
      '"scope":[{"type":"widgets","resourceName":"Widget"}]',
    );
  });

  it('asks for no scope when the operation declares no type', () => {
    expect(byId('example.createWidget').authorizer.config.payload).toContain('"scope":[]');
  });

  it('addresses the singleton when the path binds no declared type', () => {
    expect(byId('example.createWidget').authorizer.config.payload).toContain('"object":"__self__"');
    expect(byId('example.getWidgets').authorizer.config.payload).toContain('"object":"__self__"');
  });

  it('checks every operation, so what is open is a grant rather than a rule', () => {
    expect(byId('example.getHealth').authorizer.handler).toBe('remote_json');
  });

  it('takes its authenticators from the deployment', () => {
    expect(byId('example.getWidgets').authenticators).toEqual([
      { handler: 'cookie_session' },
      { handler: 'jwt' },
    ]);
    const chosen = emitRules(named(derive(doc, SERVICE)), { authenticators: ['mtls'] }) as any[];
    expect(chosen.find((r) => r.id === 'example.getWidgets').authenticators).toEqual([{ handler: 'mtls' }]);
  });

  it('carries a noop mutator on every rule', () => {
    expect(rules.every((r) => r.mutators.every((m: any) => m.handler === 'noop'))).toBe(true);
  });
});

describe('authzgen model emission', () => {
  it('declares that the namespace exists and carries the canonical stubs', () => {
    const doc = spec({
      '/widgets': { get: op('getWidgets') },
      '/widgets/{widgetId}/parts': { get: op('getWidgetParts'), post: op('addWidgetPart') },
    });
    const model = emitModel(derive(doc, SERVICE));
    expect(model).toContain('export class example implements Namespace {}');
    expect(model).toContain('export class Role implements Namespace {');
    expect(model).not.toContain('getWidgetParts');
    expect(model).not.toContain('permits');
  });
});
