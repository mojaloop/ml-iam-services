import { reconcile } from '../../src/operator/reconcile';
import { fromResource, readRegistry } from '../../src/operator/sources';

const document = (service: string, path: string, scopedBy?: string[]) => {
  const parts = path.split('/').filter(Boolean);
  const at = parts.findIndex((s) => s.startsWith('{'));
  const boundType = at > 0 ? parts[at - 1]! : undefined;
  const types = scopedBy ?? (boundType !== undefined ? [boundType] : []);
  return {
    openapi: '3.1.0',
    info: { title: service, version: '1.0.0' },
    'x-authz': { service, ...(types.length > 0 ? { resourceTypes: types } : {}) },
    servers: [{ url: '/' }],
    components: { securitySchemes: { session: { type: 'apiKey', in: 'cookie', name: 'ory_kratos_session' } } },
    paths: {
      [path]: {
        get: {
          operationId: 'list',
          summary: `Lists ${service}`,
          security: [{ session: [] }],
          ...(scopedBy ? { 'x-authz': { scopedBy } } : {}),
          responses: {
            200: { description: 'ok', content: { 'application/json': { schema: { type: 'array' } } } },
          },
        },
      },
    },
  };
};

const declared = (service: string, path: string, scopedBy?: string[], host = `${service}.test`) => ({
  origin: `AuthzDocument/${service}`,
  document: document(service, path, scopedBy),
  serving: { host },
});

const naming = (...members: Array<{ service: string; type: string }>) => ({
  resourceNames: { Thing: { label: 'Thing', members } },
});

describe('reconciling what a deployment declares', () => {
  it('composes documents from every source into one deployment', () => {
    const result = reconcile(
      [declared('alpha', '/widgets/{widgetId}'), declared('beta', '/parts/{partId}')],
      naming({ service: 'alpha', type: 'widgets' }, { service: 'beta', type: 'parts' }),
    );
    expect(result.problems).toEqual([]);
    expect(result.composition?.catalog.map((c) => c.service)).toEqual(['alpha', 'beta']);
    expect(Object.keys(result.composition?.rules ?? {})).toEqual(['alpha', 'beta']);
  });

  /**
   * A rollout that publishes half a deployment's rules is a gateway that
   * answers 404 for the other half, so nothing is published when anything is
   * wrong with any document.
   */
  it('publishes nothing when one document cannot be read', () => {
    const result = reconcile(
      [
        declared('alpha', '/widgets/{widgetId}'),
        { origin: 'AuthzDocument/broken', document: { openapi: '3.1.0', paths: {} }, serving: {} },
      ],
      naming({ service: 'alpha', type: 'widgets' }),
    );
    expect(result.composition).toBeUndefined();
    expect(result.problems).toEqual(['AuthzDocument/broken: the document root must declare x-authz.service']);
  });

  it('publishes nothing when two documents disagree', () => {
    const result = reconcile(
      [
        declared('alpha', '/widgets/{widgetId}', undefined, 'shared.test'),
        declared('alpha', '/parts/{partId}', undefined, 'shared.test'),
      ],
      naming({ service: 'alpha', type: 'widgets' }, { service: 'alpha', type: 'parts' }),
    );
    expect(result.composition).toBeUndefined();
    expect(result.problems).toContain('service alpha is registered 2 times');
  });

  it('asks the deployment to vouch for a type no path binds', () => {
    const unrouted = [declared('alpha', '/widgets', ['participants'])];
    expect(reconcile(unrouted).composition).toBeUndefined();
    expect(
      reconcile(unrouted, {
        resourceNames: {
          Participant: { label: 'Participant', members: [{ service: 'alpha', type: 'participants' }] },
        },
      }).problems,
    ).toEqual([]);
  });

  /**
   * A permission that leaves is a grant that silently means nothing, so the
   * deployment says what happens to it before the change reaches the gateway.
   */
  it('refuses a change that would strand grants, until a migration names it', () => {
    const before = reconcile([declared('alpha', '/widgets/{widgetId}')], naming({ service: 'alpha', type: 'widgets' }));
    const gadgets = naming({ service: 'alpha', type: 'gadgets' });
    const after = reconcile([declared('alpha', '/gadgets/{gadgetId}')], gadgets, before.composition?.catalog);
    expect(after.composition).toBeUndefined();
    expect(after.problems.join(' ')).toContain('alpha.list');

    const migrated = reconcile([declared('alpha', '/gadgets/{gadgetId}')], gadgets, before.composition?.catalog, {
      'alpha.list': null,
    });
    expect(migrated.problems).toEqual([]);
  });

  it('reads a document out of a custom resource the same way', () => {
    const resource = {
      metadata: { name: 'reports', generation: 3 },
      spec: {
        document: JSON.stringify(document('reports', '/reports/{reportName}')),
        url: { host: 'api.reports.test' },
      },
    };
    const result = reconcile([fromResource(resource)], naming({ service: 'reports', type: 'reports' }));
    expect(result.origins).toEqual(['AuthzDocument/reports']);
    expect(result.composition?.catalog[0]?.service).toEqual('reports');
  });

  it('refuses a custom resource carrying no document', () => {
    expect(() => fromResource({ metadata: { name: 'empty' }, spec: {} })).toThrow(/spec.document is empty/);
  });
});

describe('the registry a deployment writes', () => {
  const entries = `- spec: /authz/mcm/opt/app/src/api/openapi.yaml
  url:
    host: "api.mcm.example"
- spec: /authz/reports/opt/app/src/api/openapi.yaml
  url:
    host: "api.reports.example"
    path: "/reports"
`;

  it('reads the list a chart mounts', () => {
    expect(readRegistry(entries, 'registry.yaml')).toEqual([
      { spec: '/authz/mcm/opt/app/src/api/openapi.yaml', url: { host: 'api.mcm.example' } },
      { spec: '/authz/reports/opt/app/src/api/openapi.yaml', url: { host: 'api.reports.example', path: '/reports' } },
    ]);
  });

  it('reads the same list where a values file names it', () => {
    const values = `authz:\n${entries.replace(/^(?=.)/gm, '  ')}`;
    expect(readRegistry(values, 'values.yaml')).toEqual(readRegistry(entries, 'registry.yaml'));
  });
});
