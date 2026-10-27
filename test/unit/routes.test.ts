import { claimsOf, hostsMeet, HTTPRouteResource, reaches, readRoute, RouteRule } from '../../src/operator/routes';

const authz = { type: 'ExternalAuth' };

const route = (
  annotations: Record<string, string>,
  rules: RouteRule[],
  hostnames: string[] = ['mcm.example.test'],
): HTTPRouteResource => ({
  metadata: { name: 'mcm-api', namespace: 'mcm', annotations },
  spec: { hostnames, parentRefs: [{ name: 'external' }], rules },
});

const rule = (name: string, path = '/', extra: Partial<RouteRule> = {}): RouteRule => ({
  matches: [{ path: { type: 'PathPrefix', value: path } }],
  filters: [authz],
  backendRefs: [{ name, port: 3001 }],
  ...extra,
});

describe('reading a route', () => {
  it('keys each backend by the name the route gives it', () => {
    const read = readRoute(
      route(
        {
          'iam.mojaloop.io/mcm-api.service': 'mcm',
          'iam.mojaloop.io/mcm-reports.service': 'mcmReports',
          'iam.mojaloop.io/mcm-reports.schema': 'mcm-reports',
        },
        [rule('mcm-api', '/api'), rule('mcm-reports', '/reports')],
      ),
    );
    expect(read.problems).toEqual([]);
    expect(read.unenforced).toEqual([]);
    expect(read.backends).toEqual([
      {
        route: 'mcm/mcm-api',
        routeNamespace: 'mcm',
        namespace: 'mcm',
        name: 'mcm-api',
        port: 3001,
        service: 'mcm',
        hosts: ['mcm.example.test'],
        reaches: [{ matches: [{ type: 'PathPrefix', path: '/api' }] }],
      },
      {
        route: 'mcm/mcm-api',
        routeNamespace: 'mcm',
        namespace: 'mcm',
        name: 'mcm-reports',
        port: 3001,
        service: 'mcmReports',
        schema: 'mcm-reports',
        hosts: ['mcm.example.test'],
        reaches: [{ matches: [{ type: 'PathPrefix', path: '/reports' }] }],
      },
    ]);
  });

  it('reads nothing from a route no annotation opts in', () => {
    expect(readRoute(route({}, [rule('mcm-api')]))).toEqual({ backends: [], problems: [], unenforced: [] });
  });

  it('collects every rule reaching one backend', () => {
    const read = readRoute(
      route({ 'iam.mojaloop.io/mcm-api.service': 'mcm' }, [
        rule('mcm-api', '/api'),
        rule('mcm-api', '/health', { matches: [{ path: { type: 'Exact', value: '/health' }, method: 'GET' }] }),
      ]),
    );
    expect(read.backends).toHaveLength(1);
    expect(read.backends[0]!.reaches).toEqual([
      { matches: [{ type: 'PathPrefix', path: '/api' }] },
      { matches: [{ type: 'Exact', path: '/health', method: 'GET' }] },
    ]);
  });

  it('maps a prefix rewrite back to the path clients send', () => {
    const read = readRoute(
      route({ 'iam.mojaloop.io/mcm-api.service': 'mcm' }, [
        rule('mcm-api', '/mcm', {
          filters: [authz, { type: 'URLRewrite', urlRewrite: { path: { type: 'ReplacePrefixMatch', replacePrefixMatch: '/' } } }],
        }),
      ]),
    );
    expect(read.backends[0]!.reaches).toEqual([
      { matches: [{ type: 'PathPrefix', path: '/mcm' }], rewrite: { from: '/mcm', to: '/' } },
    ]);
  });

  it('refuses a rewrite it cannot map back', () => {
    const read = readRoute(
      route({ 'iam.mojaloop.io/mcm-api.service': 'mcm' }, [
        rule('mcm-api', '/mcm', {
          filters: [authz, { type: 'URLRewrite', urlRewrite: { path: { type: 'ReplaceFullPath', replaceFullPath: '/x' } } }],
        }),
      ]),
    );
    expect(read.backends).toEqual([]);
    expect(read.problems).toEqual(['HTTPRoute/mcm/mcm-api rule 1: this URLRewrite cannot be mapped back to the paths clients send']);
  });

  it('refuses a regular expression match', () => {
    const read = readRoute(
      route({ 'iam.mojaloop.io/mcm-api.service': 'mcm' }, [
        rule('mcm-api', '/', { matches: [{ path: { type: 'RegularExpression', value: '/v[0-9]+' } }] }),
      ]),
    );
    expect(read.backends).toEqual([]);
    expect(read.problems).toEqual([
      'HTTPRoute/mcm/mcm-api rule 1: a RegularExpression path match cannot be read as a set of operations',
    ]);
  });

  it('refuses a rule that splits traffic across backends', () => {
    const read = readRoute(
      route(
        { 'iam.mojaloop.io/mcm-v1.service': 'mcm', 'iam.mojaloop.io/mcm-v2.service': 'mcm' },
        [rule('mcm-v1', '/', { backendRefs: [{ name: 'mcm-v1', port: 3001, weight: 90 }, { name: 'mcm-v2', port: 3001, weight: 10 }] })],
      ),
    );
    expect(read.backends).toEqual([]);
    expect(read.problems).toEqual(['HTTPRoute/mcm/mcm-api rule 1: splits traffic across mcm-v1, mcm-v2, which is refused']);
  });

  it('reads a backend weighted to zero as not reached', () => {
    const read = readRoute(
      route(
        { 'iam.mojaloop.io/mcm-v1.service': 'mcm', 'iam.mojaloop.io/mcm-v2.service': 'mcm' },
        [rule('mcm-v1', '/', { backendRefs: [{ name: 'mcm-v1', port: 3001 }, { name: 'mcm-v2', port: 3001, weight: 0 }] })],
      ),
    );
    expect(read.problems).toEqual([]);
    expect(read.backends.map((b) => b.name)).toEqual(['mcm-v1']);
  });

  it('says loudly when a keyed backend is reached without asking the platform', () => {
    const read = readRoute(route({ 'iam.mojaloop.io/mcm-api.service': 'mcm' }, [rule('mcm-api', '/', { filters: [] })]));
    expect(read.backends).toHaveLength(1);
    expect(read.unenforced).toEqual(['HTTPRoute/mcm/mcm-api rule 1: sends mcm-api requests without the ExternalAuth filter']);
  });

  it('names every backend of an opted-in route that carries no key', () => {
    const read = readRoute(
      route({ 'iam.mojaloop.io/mcm-api.service': 'mcm' }, [rule('mcm-api', '/api'), rule('mcm-ui', '/')]),
    );
    expect(read.backends.map((b) => b.name)).toEqual(['mcm-api']);
    expect(read.problems).toEqual([
      'HTTPRoute/mcm/mcm-api: backend mcm-ui has no iam.mojaloop.io/mcm-ui.service; nothing it answers is authorized',
    ]);
  });

  it('refuses a key that names no backend, or no setting it knows', () => {
    const read = readRoute(
      route(
        {
          'iam.mojaloop.io/mcm-api.service': 'mcm',
          'iam.mojaloop.io/mcm-apl.service': 'mcm',
          'iam.mojaloop.io/mcm-api.scope': 'x',
          'iam.mojaloop.io/service': 'mcm',
        },
        [rule('mcm-api')],
      ),
    );
    expect(read.problems.sort()).toEqual([
      'HTTPRoute/mcm/mcm-api: iam.mojaloop.io/mcm-api.scope is not <backend>.service or <backend>.schema',
      'HTTPRoute/mcm/mcm-api: iam.mojaloop.io/mcm-apl.* names no backend of this route',
      'HTTPRoute/mcm/mcm-api: iam.mojaloop.io/service is not <backend>.service or <backend>.schema',
    ]);
  });

  it('refuses a schema with no service', () => {
    const read = readRoute(
      route({ 'iam.mojaloop.io/mcm-api.service': 'mcm', 'iam.mojaloop.io/mcm-ui.schema': 'ui' }, [
        rule('mcm-api', '/api'),
        rule('mcm-ui', '/'),
      ]),
    );
    expect(read.problems).toContain('HTTPRoute/mcm/mcm-api: mcm-ui has a schema but no iam.mojaloop.io/mcm-ui.service');
  });

  it('refuses one backend name reached in two namespaces', () => {
    const read = readRoute(
      route({ 'iam.mojaloop.io/api.service': 'mcm' }, [
        rule('api', '/a'),
        rule('api', '/b', { backendRefs: [{ name: 'api', namespace: 'other', port: 3001 }] }),
      ]),
    );
    expect(read.backends).toEqual([]);
    expect(read.problems).toEqual([
      'HTTPRoute/mcm/mcm-api: backend api is referenced in mcm and other, which its key cannot tell apart',
    ]);
  });

  it('refuses a backend whose name is too long to key', () => {
    const name = 'b'.repeat(56);
    const read = readRoute(route({ 'iam.mojaloop.io/mcm-api.service': 'mcm' }, [rule('mcm-api', '/api'), rule(name, '/')]));
    expect(read.problems).toEqual([`HTTPRoute/mcm/mcm-api: backend ${name} is too long to key; nothing it answers is authorized`]);
  });

  it('refuses a backend reference with no port', () => {
    const read = readRoute(
      route({ 'iam.mojaloop.io/mcm-api.service': 'mcm' }, [rule('mcm-api', '/', { backendRefs: [{ name: 'mcm-api' }] })]),
    );
    expect(read.backends).toEqual([]);
    expect(read.problems).toEqual(['HTTPRoute/mcm/mcm-api rule 1: backend mcm-api names no port']);
  });

  it('inherits the hostnames of the listeners a route attaches to', () => {
    const annotated = route({ 'iam.mojaloop.io/mcm-api.service': 'mcm' }, [rule('mcm-api')], []);
    expect(readRoute(annotated, ['*.example.test']).backends[0]!.hosts).toEqual(['*.example.test']);
    expect(readRoute(annotated).problems).toEqual(['HTTPRoute/mcm/mcm-api: names no hostname and its listeners declare none']);
  });
});

describe('what a route claims', () => {
  it('claims every prefix its rules answer, keyed or not', () => {
    expect(claimsOf(route({}, [rule('mcm-api', '/api'), rule('mcm-ui', '/')]))).toEqual([
      { hosts: ['mcm.example.test'], path: '/api' },
      { hosts: ['mcm.example.test'], path: '/' },
    ]);
  });

  it('meets another host list on a shared name or a one-label wildcard', () => {
    expect(hostsMeet(['a.example.test'], ['a.example.test'])).toBe(true);
    expect(hostsMeet(['*.example.test'], ['a.example.test'])).toBe(true);
    expect(hostsMeet(['a.example.test'], ['*.example.test'])).toBe(true);
    expect(hostsMeet(['*.example.test'], ['a.b.example.test'])).toBe(false);
    expect(hostsMeet(['a.example.test'], ['b.example.test'])).toBe(false);
  });

  it('sends a request through a reach by method, exact path or whole segments of a prefix', () => {
    const reach = {
      matches: [
        { type: 'PathPrefix' as const, path: '/api/' },
        { type: 'Exact' as const, path: '/health', method: 'GET' },
      ],
    };
    expect(reaches(reach, 'POST', '/api/dfsps')).toBe(true);
    expect(reaches(reach, 'GET', '/api')).toBe(true);
    expect(reaches(reach, 'GET', '/apix')).toBe(false);
    expect(reaches(reach, 'GET', '/health')).toBe(true);
    expect(reaches(reach, 'POST', '/health')).toBe(false);
    expect(reaches(reach, 'GET', '/health/live')).toBe(false);
    expect(reaches({ matches: [{ type: 'PathPrefix', path: '/' }] }, 'GET', '/anything')).toBe(true);
  });
});
