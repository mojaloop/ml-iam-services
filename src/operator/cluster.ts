import { createHash } from 'node:crypto';

import { GenericKind, K8s, kind, RegisterKind, WatchCfg } from 'kubernetes-fluent-client';

import { HTTPRouteResource } from './routes';
import { AuthzDocumentResource } from './sources';

/**
 * The cluster side of reconciling: the routes that key backends, the
 * documents they name, and where the result is published and reported.
 */

/** A document an HTTPRoute names for one of its backends. */
export class AuthzDocument extends GenericKind {
  declare spec?: { document?: Record<string, unknown> };
  declare status?: {
    /** `Accepted`, `Refused` or `Unreferenced`, so `kubectl get` tells the story. */
    state?: string;
    /** The permission prefixes that read this document. */
    service?: string;
    /** What refused it, in the words the composer used. */
    messages?: string[];
    /** The generation this status answers, so a stale status is visible. */
    observedGeneration?: number;
  };
}

RegisterKind(AuthzDocument, {
  group: 'mojaloop.io',
  version: 'v1',
  kind: 'AuthzDocument',
  plural: 'authzdocuments',
});

export class HTTPRoute extends GenericKind {
  declare spec?: HTTPRouteResource['spec'];
}

RegisterKind(HTTPRoute, {
  group: 'gateway.networking.k8s.io',
  version: 'v1',
  kind: 'HTTPRoute',
  plural: 'httproutes',
});

export class Gateway extends GenericKind {
  declare spec?: { listeners?: Array<{ name?: string; hostname?: string }> };
}

RegisterKind(Gateway, {
  group: 'gateway.networking.k8s.io',
  version: 'v1',
  kind: 'Gateway',
  plural: 'gateways',
});

export const listRoutes = async (): Promise<HTTPRouteResource[]> =>
  (await K8s(HTTPRoute).Get()).items as HTTPRouteResource[];

export const listDocuments = async (): Promise<AuthzDocumentResource[]> =>
  (await K8s(AuthzDocument).Get()).items as AuthzDocumentResource[];

export const listGateways = async (): Promise<Gateway[]> => (await K8s(Gateway).Get()).items;

/**
 * Calls back whenever a route, a document or a gateway appears, changes or
 * leaves. The client keeps each connection and resource version, so a
 * reconnect resumes where it left off and a resync catches what changed while
 * it was gone.
 */
export const watchInputs = async (
  onChange: () => Promise<void>,
  cfg: WatchCfg = {},
): Promise<{ close: () => void }> => {
  const watchers = [
    K8s(HTTPRoute).Watch(async () => onChange(), cfg),
    K8s(AuthzDocument).Watch(async () => onChange(), cfg),
    K8s(Gateway).Watch(async () => onChange(), cfg),
  ];
  await Promise.all(watchers.map((w) => w.start()));
  return { close: () => watchers.forEach((w) => w.close()) };
};

/** Tells a document's author what became of it. */
export const reportOn = async (
  namespace: string,
  name: string,
  status: { state: string; service?: string; messages: string[]; observedGeneration?: number },
): Promise<void> => {
  await K8s(AuthzDocument, { namespace, name }).PatchStatus({
    metadata: { name, namespace },
    status,
  } as AuthzDocument);
};

/**
 * Reports a problem on the route it concerns. One Event per distinct message,
 * named by its digest, so every pass re-applies the same object instead of
 * adding another.
 */
export const reportOnRoute = async (namespace: string, route: string, message: string): Promise<void> => {
  const digest = createHash('sha256').update(`${route}\n${message}`).digest('hex').slice(0, 16);
  const now = new Date().toISOString();
  await K8s(kind.CoreEvent).Apply(
    {
      metadata: { name: `${route}.authz.${digest}`, namespace },
      involvedObject: { apiVersion: 'gateway.networking.k8s.io/v1', kind: 'HTTPRoute', name: route, namespace },
      reason: 'AuthorizationRefused',
      message,
      type: 'Warning',
      source: { component: 'ml-iam-services' },
      firstTimestamp: now as unknown as Date,
      lastTimestamp: now as unknown as Date,
    },
    { force: true },
  );
};

/**
 * Publishes what a reconcile produced, as the files the gateway and Keto boot
 * from. Server-side apply, so the object converges on what this process says.
 */
export const publish = async (
  namespace: string,
  name: string,
  data: Record<string, string>,
): Promise<void> => {
  await K8s(kind.ConfigMap).Apply(
    {
      metadata: {
        name,
        namespace,
        labels: { 'app.kubernetes.io/managed-by': 'ml-iam-services' },
      },
      data,
    },
    { force: true },
  );
};
