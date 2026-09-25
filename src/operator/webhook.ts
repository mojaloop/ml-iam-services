import { derive } from '../authzgen/derive';
import { AuthzDocumentResource, fromResource } from './sources';

/**
 * Admission for AuthzDocument: the same reader the composition uses, run when
 * the object is written, so a document that would never compose is refused
 * with the reason instead of stored. Which prefix a document answers under is
 * the route's, unknown here, so it is read under a stand-in one.
 */

export const WEBHOOK_PATH = '/validate-authzdocument';

interface AdmissionReview {
  apiVersion?: string;
  kind?: string;
  request?: { uid?: string; operation?: string; object?: AuthzDocumentResource };
}

export async function review(body: unknown): Promise<AdmissionReview & { response: object }> {
  const request = (body as AdmissionReview)?.request;
  const uid = request?.uid ?? '';
  const answer = (allowed: boolean, message?: string) => ({
    apiVersion: 'admission.k8s.io/v1',
    kind: 'AdmissionReview',
    response: { uid, allowed, ...(message !== undefined ? { status: { code: 422, message } } : {}) },
  });

  const resource = request?.object;
  if (resource === undefined) return answer(false, 'the review carries no object');
  try {
    derive(await fromResource(resource), 'document');
    return answer(true);
  } catch (error) {
    return answer(false, (error as Error).message);
  }
}
