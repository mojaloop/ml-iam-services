import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import { StatusCodes } from 'http-status-codes';
import { GenericClass, GenericKind, K8s, kind, RegisterKind, WatchCfg } from 'kubernetes-fluent-client';
import { WatchPhase } from 'kubernetes-fluent-client/dist/fluent/shared-types';

import { Localized } from '../authzgen/compose';
import { ObjectRef } from '../authzgen/problem';
import type { LeaseRecord, LeaseSpec, LeaseStore } from '../controller/leader';
import { Condition } from '../iam/conditions';
import { Within } from '../iam/exclusions';
import { COMPONENT, GROUP, Kind, MANAGED_BY, VERSION } from '../iam/kinds';
import { HeldBy } from '../iam/roles';
import { GATEWAY_KIND, HTTPRouteResource } from './routes';
import { AuthzDocumentResource } from './sources';

/**
 * The cluster side of reconciling: the routes that key backends, the
 * documents they name, the deployment's roles, separation rules and resource
 * names, and where the result is published and reported.
 */

export { GROUP, MANAGED_BY } from '../iam/kinds';

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
    title?: Localized;
    description?: Localized;
    heldBy?: HeldBy;
    grants?: Array<{ permission: string; resources?: Record<string, string | string[]> }>;
  };
  declare status?: ObjectStatus;
}

export class AuthzSeparation extends GenericKind {
  declare spec?: {
    description?: Localized;
    within?: Within;
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

for (const [model, name] of [
  [AuthzDocument, Kind.document],
  [AuthzRole, Kind.role],
  [AuthzSeparation, Kind.separation],
  [AuthzResourceName, Kind.resourceName],
] as const) {
  RegisterKind(model, { group: GROUP, version: VERSION, kind: name, plural: `${name.toLowerCase()}s` });
}

export type DeploymentKind = typeof AuthzDocument | typeof AuthzRole | typeof AuthzSeparation | typeof AuthzResourceName;

const GATEWAY_API = { group: 'gateway.networking.k8s.io', version: 'v1' } as const;
const ROUTE_KIND = 'HTTPRoute';

export class HTTPRoute extends GenericKind {
  declare spec?: HTTPRouteResource['spec'];
}

RegisterKind(HTTPRoute, { ...GATEWAY_API, kind: ROUTE_KIND, plural: 'httproutes' });

export class Gateway extends GenericKind {
  declare spec?: { listeners?: Array<{ name?: string; hostname?: string }> };
}

RegisterKind(Gateway, { ...GATEWAY_API, kind: GATEWAY_KIND, plural: 'gateways' });

export class Lease extends GenericKind {
  declare spec?: {
    holderIdentity?: string;
    leaseDurationSeconds?: number;
    acquireTime?: string;
    renewTime?: string;
    leaseTransitions?: number;
  };
}

RegisterKind(Lease, {
  group: 'coordination.k8s.io',
  version: 'v1',
  kind: 'Lease',
  plural: 'leases',
});

const recordOf = (lease: Lease): LeaseRecord => ({
  ...(lease.spec?.holderIdentity ? { holder: lease.spec.holderIdentity } : {}),
  ...(lease.spec?.leaseDurationSeconds !== undefined ? { durationSeconds: lease.spec.leaseDurationSeconds } : {}),
  ...(lease.spec?.acquireTime ? { acquireTime: lease.spec.acquireTime } : {}),
  ...(lease.spec?.renewTime ? { renewTime: lease.spec.renewTime } : {}),
  ...(lease.spec?.leaseTransitions !== undefined ? { transitions: lease.spec.leaseTransitions } : {}),
  version: lease.metadata!.resourceVersion!,
});

/** A Lease's times are MicroTime, RFC 3339 with six fractional digits. */
const micro = (iso: string | undefined): string | undefined => iso?.replace(/\.(\d{3})Z$/, '.$1000Z');

const leaseSpec = (spec: LeaseSpec): NonNullable<Lease['spec']> => ({
  holderIdentity: spec.holder ?? '',
  ...(spec.durationSeconds !== undefined ? { leaseDurationSeconds: spec.durationSeconds } : {}),
  ...(spec.acquireTime !== undefined ? { acquireTime: micro(spec.acquireTime)! } : {}),
  ...(spec.renewTime !== undefined ? { renewTime: micro(spec.renewTime)! } : {}),
  ...(spec.transitions !== undefined ? { leaseTransitions: spec.transitions } : {}),
});

/**
 * The Lease the controller's replicas elect their leader through. The release
 * creates it, so the controller only reads, watches and patches that one
 * object. A patch tests the version it was read at, so of two replicas
 * writing at once exactly one lands.
 */
/** A lease write lands only on the version it read, and replaces the spec whole. */
const UNCHANGED_SINCE = { op: 'test', path: '/metadata/resourceVersion' } as const;
const WRITE_SPEC = { op: 'add', path: '/spec' } as const;

export const leaseStore = (namespace: string, name: string): LeaseStore => ({
  read: async () => recordOf(await K8s(Lease).InNamespace(namespace).Get(name)),
  write: async (spec, version) => {
    try {
      return recordOf(
        await K8s(Lease, { namespace, name }).Patch([
          { ...UNCHANGED_SINCE, value: version },
          { ...WRITE_SPEC, value: leaseSpec(spec) },
        ]),
      );
    } catch (error) {
      const status = (error as { status?: number }).status;
      if (status === StatusCodes.CONFLICT || status === StatusCodes.UNPROCESSABLE_ENTITY) return undefined;
      throw error;
    }
  },
  watch: async (onRecord) => {
    const watcher = K8s(Lease, { namespace, name }).Watch(async (lease, phase) => {
      if (phase !== WatchPhase.Deleted) onRecord(recordOf(lease));
    });
    await watcher.start();
    return { close: () => watcher.close() };
  },
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
    if (phase === WatchPhase.Deleted) {
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

const SERVICE_NAME = 'kubernetes.io/service-name';

/** The pods a slice sends traffic to, which a rollout replaces: each by its uid, or its addresses when it has none. */
const served = (slice: InstanceType<typeof kind.EndpointSlice>): Set<string | string[]> =>
  new Set(
    (slice.endpoints ?? [])
      .filter((e) => e.conditions?.ready !== false)
      .map((e): string | string[] => e.targetRef?.uid ?? e.addresses),
  );

/**
 * Calls back when the pods behind a Service the caller reads change, which
 * is when what that Service serves can change without any route moving.
 */
export const watchBackends = async (
  reads: (service: ObjectRef) => boolean,
  onChange: () => Promise<void>,
): Promise<{ close: () => void }> => {
  const seen = new Map<string | undefined, Set<string | string[]>>();
  const watcher = K8s(kind.EndpointSlice).Watch(async (slice, phase) => {
    const name = slice.metadata?.labels?.[SERVICE_NAME];
    if (name === undefined || !reads({ namespace: slice.metadata?.namespace ?? '', name })) return;
    const uid = slice.metadata?.uid;
    const now = phase === WatchPhase.Deleted ? new Set<string | string[]>() : served(slice);
    if (isDeepStrictEqual(seen.get(uid), now)) return;
    const first = !seen.has(uid);
    seen.set(uid, now);
    if (!first) await onChange();
  });
  await watcher.start();
  return { close: () => watcher.close() };
};

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

const REFUSED_REASON = 'AuthorizationRefused';
const EventType = { warning: 'Warning' } as const;

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
      involvedObject: { apiVersion: `${GATEWAY_API.group}/${GATEWAY_API.version}`, kind: ROUTE_KIND, name: route, namespace },
      reason: REFUSED_REASON,
      message,
      type: EventType.warning,
      source: { component: COMPONENT },
      firstTimestamp: now as unknown as Date,
      lastTimestamp: now as unknown as Date,
    },
    { force: true },
  );
};

/** A ConfigMap's data, or nothing when there is no such ConfigMap. */
export const readConfigMap = async (namespace: string, name: string): Promise<Record<string, string> | undefined> => {
  try {
    return (await K8s(kind.ConfigMap).InNamespace(namespace).Get(name)).data ?? {};
  } catch (error) {
    if ((error as { status?: number }).status === StatusCodes.NOT_FOUND) return undefined;
    throw error;
  }
};

/** Writes a role's spec, as the object the IAM keeps for it. */
export const applyRole = async (role: AuthzRole): Promise<void> => {
  await K8s(AuthzRole).Apply(role, { force: true });
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
        labels: MANAGED_BY,
      },
      data,
    },
    { force: true },
  );
};
