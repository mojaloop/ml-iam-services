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

const spec = (paths: Record<string, unknown>, resourceTypes: string[] = typesOf(paths)) => ({
  openapi: '3.0.1',
  info: { title: 'Example API' },
  servers: [{ url: '/api' }],
  'x-authz': { service: 'example', ...(resourceTypes.length > 0 ? { resourceTypes } : {}) },
  components: { securitySchemes: schemes },
  paths,
});

const permissionOf = (doc: any, id: string) => {
  const found = derive(doc).permissions.find((p) => p.id === id);
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

  it('honours an explicit permission name', () => {
    const doc = spec({
      '/widgets/{widgetId}/keys': {
        post: op('postWidgetKeys', { 'x-authz': { permission: 'widget.issueKeys' } }),
      },
    });
    const p = permissionOf(doc, 'example.widget.issueKeys');
    expect(p.name).toBe('widget.issueKeys');
    expect(p.operationId).toBe('postWidgetKeys');
  });

  it('supports an empty resource list where the outer id is reference data', () => {
    const doc = spec({
      '/regions/{regionId}/widgets': { get: op('getWidgetsByRegion', { 'x-authz': { scopedBy: [] } }) },
      '/widgets/{widgetId}': { get: op('getWidget') },
    });
    expect(permissionOf(doc, 'example.getWidgetsByRegion').scopedBy).toEqual([]);
    expect(derive(doc).resourceTypes).toEqual(['widgets']);
  });

  it('counts every parameter towards the capture index, bound or not', () => {
    const doc = spec({
      '/{tenant}/widgets/{widgetId}': { get: op('getTenantWidget', { 'x-authz': { scopedBy: [{ widgets: 'widgetId' }] } }) },
    });
    expect(permissionOf(doc, 'example.getTenantWidget').scopedBy).toEqual([
      { param: 'widgetId', type: 'widgets', captureIndex: 2 },
    ]);
  });

  it('marks security: [] as anonymous', () => {
    const doc = spec({ '/health': { get: op('getHealth', { security: [] }) } });
    const p = permissionOf(doc, 'example.getHealth');
    expect(p.anonymous).toBe(true);
    expect(p.authenticators).toEqual(['noop']);
  });

  it('maps security schemes to authenticators', () => {
    const doc = spec({
      '/widgets/{widgetId}': { get: op('getWidget', { security: [{ session: [] }, { machineToken: [] }] }) },
    });
    expect(permissionOf(doc, 'example.getWidget').authenticators).toEqual(['cookie_session', 'jwt']);
  });

  describe('rejections', () => {
    const rejects = (doc: unknown, message: RegExp) => {
      expect(() => derive(doc)).toThrow(DocumentError);
      expect(() => derive(doc)).toThrow(message);
    };

    it('requires x-authz.service at the root', () => {
      const doc = spec({ '/widgets': { get: op('getWidgets') } });
      delete (doc as any)['x-authz'];
      rejects(doc, /x-authz.service/);
    });

    it('requires a summary for the catalog', () => {
      rejects(spec({ '/widgets': { get: { operationId: 'getWidgets', security: [] } } }), /summary is required/);
    });

    it('requires security to be explicit on every operation', () => {
      rejects(spec({ '/widgets': { get: { operationId: 'getWidgets', summary: 'x' } } }), /security must be declared/);
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
      doc['x-authz'] = { service: 'example', scopes: [] };
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
      ['it is anonymous', { security: [] }],
    ])('accepts a collection GET when %s', (_label, extra) => {
      const doc = spec({
        '/widgets': { get: op('getWidgets', { ...listOf({ type: 'object' }), ...extra }) },
        '/widgets/{widgetId}': { get: op('getWidget') },
      });
      expect(() => derive(doc)).not.toThrow();
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
        '/b': { get: op('other', { 'x-authz': { permission: 'same' } }) },
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
  const rules = emitRules(named(derive(doc))) as any[];
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
    const served = emitRules(derive(doc), { host: 'api.example.test' }) as any[];
    for (const rule of served) expect(rule.match.url).not.toContain('{');
    expect(byIdIn(served, 'example.getWidgets').match.url).toBe('<http|https>://api.example.test/api/widgets<$>');
  });

  it('mounts under the prefix a deployment gives it', () => {
    const served = emitRules(derive(doc), { host: 'portal.example.test', path: '/widgets/' }) as any[];
    expect(byIdIn(served, 'example.getWidgets').match.url).toBe(
      '<http|https>://portal.example.test/widgets/api/widgets<$>',
    );
  });

  it('gives an operation at the root the whole mount, an application its own routes resolve within', () => {
    const app = {
      openapi: '3.0.1',
      info: { title: 'Example App' },
      servers: [{ url: '/' }],
      'x-authz': { service: 'exampleApp' },
      components: { securitySchemes: schemes },
      paths: { '/': { get: op('viewApp', { 'x-authz': { scopedBy: [] } }) } },
    };
    const served = emitRules(derive(app), { host: 'app.example.test' }) as any[];
    expect(byIdIn(served, 'exampleApp.viewApp').match.url).toBe('<http|https>://app.example.test<(?:/.*)?>');
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

  it('leaves anonymous operations unauthorized', () => {
    expect(byId('example.getHealth').authorizer).toEqual({ handler: 'allow' });
    expect(byId('example.getHealth').authenticators).toEqual([{ handler: 'noop' }]);
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
    const model = emitModel(derive(doc));
    expect(model).toContain('export class example implements Namespace {}');
    expect(model).toContain('export class Role implements Namespace {');
    expect(model).not.toContain('getWidgetParts');
    expect(model).not.toContain('permits');
  });
});
