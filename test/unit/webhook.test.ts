import { review } from '../../src/operator/webhook';

const admission = (document: unknown) => ({
  apiVersion: 'admission.k8s.io/v1',
  kind: 'AdmissionReview',
  request: {
    uid: 'u-1',
    operation: 'CREATE',
    object: { metadata: { name: 'hubble-ui', namespace: 'cilium' }, spec: { document } },
  },
});

const document = (summary?: string) => ({
  openapi: '3.1.0',
  info: { title: 'Hubble UI', version: '1.0' },
  paths: {
    '/': {
      get: {
        operationId: 'view',
        ...(summary !== undefined ? { summary } : {}),
        'x-authz': { scopedBy: [] },
        responses: { 200: { description: 'The application' } },
      },
    },
  },
});

describe('AuthzDocument admission', () => {
  it('admits a document the composition can read, answering the review it was asked', async () => {
    expect((await review(admission(document('Opens the UI')))).response).toEqual({ uid: 'u-1', allowed: true });
  });

  it('refuses a document the composition would refuse, with its reason', async () => {
    expect((await review(admission(document()))).response).toEqual({
      uid: 'u-1',
      allowed: false,
      status: { code: 422, message: 'GET /: summary is required for the catalog' },
    });
  });

  it('refuses a document older than OpenAPI 3.1', async () => {
    const answer = await review(admission({ ...document('Opens the UI'), openapi: '3.0.3' }));
    expect(answer.response).toMatchObject({
      allowed: false,
      status: { message: 'AuthzDocument/cilium/hubble-ui: OpenAPI 3.0 is not supported; the document must declare 3.1 or later' },
    });
  });

  it('refuses a document written as text', async () => {
    const answer = await review(admission('openapi: 3.1.0'));
    expect(answer.response).toMatchObject({
      allowed: false,
      status: { message: 'AuthzDocument/cilium/hubble-ui: spec.document is not an OpenAPI document' },
    });
  });
});
