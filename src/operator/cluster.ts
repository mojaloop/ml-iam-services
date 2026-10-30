import { createHash } from 'node:crypto';

import { GenericClass, GenericKind, K8s, kind, RegisterKind, WatchCfg } from 'kubernetes-fluent-client';

import { Condition } from '../iam/conditions';
import { HTTPRouteResource } from './routes';
import { AuthzDocumentResource } from './sources';

/**
 * The cluster side of reconciling: the routes that key backends, the
 * documents they name, the deployment's roles, separation rules and resource
 * names, and where the result is published and reported.
 */

export const GROUP = 'iam.mojaloop.io';

export interface ObjectStatus {
  observedGeneration?: number;
  conditions?: Condition[];
  [field: string]: unknown;
}

export class AuthzDocument extends GenericKind {
  declare spec?: { document?: Record<string, unknown> };
  declare status?: ObjectStatus;
}

export class AuthzRole extends GenericKind {
  declare spec?: {
    title?: string;
    description?: string;
    heldBy?: 'authenticated';
    grants?: Array<{ permission: string; resources?: Record<string, string | string[]> }>;
  };
  declare status?: ObjectStatus;
}

export class AuthzSeparation extends GenericKind {
  declare spec?: {
    description?: string;
    within?: 'subject' | 'resource';
    resourceName?: string;
    groups?: string[][];
  };
  declare status?: ObjectStatus;
}

export class AuthzResourceName extends GenericKind {
  declare spec?: {
    label?: string | Record<string, string>;
    description?: string | Record<string, string>;
    members?: Array<{ service: string; type: string }>;
    source?: { url: string; list?: string; id: string; label?: string };
  };
  declare status?: ObjectStatus;
}

for (const [model, name, plural] of [
  [AuthzDocument, 'AuthzDocument', 'authzdocuments'],
  [AuthzRole, 'AuthzRole', 'authzroles'],
  [AuthzSeparation, 'AuthzSeparation', 'authzseparations'],
  [AuthzResourceName, 'AuthzResourceName', 'authzresourcenames'],
] as const) {
  RegisterKind(model, { group: GROUP, version: 'v1', kind: name, plural });
}

export type DeploymentKind = typeof AuthzDocument | typeof AuthzRole | typeof AuthzSeparation | typeof AuthzResourceName;

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

export const listRoles = async (): Promise<AuthzRole[]> => (await K8s(AuthzRole).Get()).items;

export const listSeparations = async (): Promise<AuthzSeparation[]> => (await K8s(AuthzSeparation).Get()).items;

export const listResourceNames = async (): Promise<AuthzResourceName[]> => (await K8s(AuthzResourceName).Get()).items;

/**
 * What a change has to touch to matter: the spec, which moves the
 * generation, or a route's annotations, which do not. A status the IAM wrote
 * itself moves neither, so writing one never sets off another pass.
 */
const significance = (object: GenericKind): string =>
  JSON.stringify([object.metadata?.generation, object.metadata?.annotations ?? {}]);

const watching = <T extends GenericClass>(model: T, onChange: () => Promise<void>, cfg: WatchCfg) => {
  const seen = new Map<string, string>();
  return K8s(model).Watch(async (object, phase) => {
    const uid = object.metadata?.uid ?? `${object.metadata?.namespace}/${object.metadata?.name}`;
    if ((phase as string) === 'DELETED') {
      seen.delete(uid);
      return onChange();
    }
    const now = significance(object);
    if (seen.get(uid) === now) return;
    seen.set(uid, now);
    return onChange();
  }, cfg);
};

/**
 * Calls back whenever a route, a gateway or a document appears, changes or
 * leaves. The client keeps each connection and resource version, so a
 * reconnect resumes where it left off and a resync catches what changed while
 * it was gone.
 */
export const watchInputs = async (
  onChange: () => Promise<void>,
  cfg: WatchCfg = {},
): Promise<{ close: () => void }> => watchAll([HTTPRoute, AuthzDocument, Gateway, AuthzResourceName], onChange, cfg);

/** Calls back whenever a role or a separation rule appears, changes or leaves. */
export const watchRoles = async (
  onChange: () => Promise<void>,
  cfg: WatchCfg = {},
): Promise<{ close: () => void }> => watchAll([AuthzRole, AuthzSeparation], onChange, cfg);

const watchAll = async (
  models: GenericClass[],
  onChange: () => Promise<void>,
  cfg: WatchCfg,
): Promise<{ close: () => void }> => {
  const watchers = models.map((model) => watching(model, onChange, cfg));
  await Promise.all(watchers.map((w) => w.start()));
  return { close: () => watchers.forEach((w) => w.close()) };
};

/** Writes what became of an object back onto it. */
export const setStatus = async (
  model: DeploymentKind,
  namespace: string,
  name: string,
  status: ObjectStatus,
): Promise<void> => {
  await K8s(model, { namespace, name }).PatchStatus({ metadata: { name, namespace }, status } as never);
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
