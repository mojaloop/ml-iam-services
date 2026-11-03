import { readFileSync, watch } from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import Fastify, { FastifyInstance } from 'fastify';

import { ANNOUNCED_ETAG } from '../api/vocabulary';
import { Composition as Composed, ResourceNames } from '../authzgen/compose';
import { ketoNamespace } from '../authzgen/keto-name';
import { serviceOf } from '../authzgen/permission';
import { messagesOf } from '../authzgen/problem';
import { ServiceCatalog } from '../authzgen/types';
import { ALL_INTERFACES } from '../http/address';
import { closeOnSignals } from '../http/backend';
import { Reason } from '../iam/conditions';
import { heldInstances } from '../iam/exclusions';
import { advance, EMPTY, History } from '../iam/history';
import { KetoWriter } from '../iam/keto';
import { API_VERSION, Kind } from '../iam/kinds';
import { KratosAdmin } from '../iam/kratos';
import { ROLE_NAMESPACE } from '../iam/materialize';
import { DeploymentObject } from '../iam/objects';
import { ownNames, ownResources, ownRoleName, recordOwn, servedNames } from '../iam/own';
import { Provisioner } from '../iam/provisioner';
import { Affected, Applied } from '../iam/reconcile';
import { RoleSync, RoleView, RuleView } from '../iam/role-sync';
import { indexCatalogs, RolesFile } from '../iam/roles';
import { Logged } from '../logged';
import {
  applyRole,
  AuthzResourceName,
  AuthzRole,
  AuthzSeparation,
  leaseStore,
  listDocuments,
  listResourceNames,
  listRoles,
  listSeparations,
  MANAGED_BY,
  ObjectStatus,
  publish,
  readConfigMap,
  setStatus,
  watchRoles,
} from '../operator/cluster';
import { Operator } from '../operator/server';
import { AdmissionContext, review, WEBHOOK_PATH } from '../operator/webhook';
import { Composition, controllerApi, serially, tagOf } from './api';
import { config, leaseTiming, replica } from './config';
import { Elector } from './leader';

export type { Composition } from './api';

/** Every Keto namespace applying these roles writes into. */
const namespacesOf = (file: RolesFile): string[] => [
  ROLE_NAMESPACE,
  ...new Set(
    Object.values(file.roles).flatMap((role) => role.grants.map((g) => ketoNamespace(serviceOf(g.permission)))),
  ),
];

export async function waitForModel(keto: KetoWriter, namespace: string): Promise<void> {
  for (;;) {
    try {
      if ((await keto.namespaces()).includes(namespace)) return;
    } catch {
      /* empty */
    }
    console.log(`waiting for keto to read the model, namespace ${namespace}`);
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}

/** Where an Ory service says it is ready. */
const ORY_READY = '/health/ready';

const answersReady = async (url: string): Promise<boolean> => {
  try {
    return (await fetch(url)).ok;
  } catch {
    return false;
  }
};

/** Keto and Kratos come up alongside this, so first refusal is not a verdict. */
async function waitFor(url: string, name: string): Promise<void> {
  while (!(await answersReady(url))) {
    console.log(`waiting for ${name} at ${url}`);
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}

export interface StartOptions {
  adminEmail?: string;
  /** Without one, a created admin is invited by email to set a password. */
  adminPassword?: string;
  adminRole?: string;
  kratosAdminUrl?: string;
  kratosPublicUrl?: string;
  /** The namespace the composition is published into, which is also where roles composed through the API live. */
  namespace?: string;
  /** The ConfigMap the gateway and Keto read the composed rules and model from. */
  publishAs?: string;
  /** The ConfigMap the composition's ETag is announced in, which the API process watches. */
  announceAs?: string;
  /** The ConfigMap every permission ever composed is kept in, to tell a renamed one from a removed one. */
  historyAs?: string;
  /** The prefix the IAM's own route gives its public API, whose roles and permissions it records itself. */
  servesAs?: string;
  /** A directory holding tls.crt and tls.key, to answer admission over HTTPS. */
  webhookCertDir?: string;
  /** The Lease the replicas elect their leader through; without one, this process leads alone. */
  lease?: string;
}

const WEBHOOK_PORT = 9443;
/** An AdmissionReview carries the object and the one it replaces, each within etcd's 1.5 MiB request limit. */
const ADMISSION_BODY_LIMIT = 4 * 1024 * 1024;

/** The files a mounted certificate secret holds. */
const TLS = { cert: 'tls.crt', key: 'tls.key' } as const;

/** What a resource name's object shows of what the IAM last listed of it. */
type ResourceNameStatus = ObjectStatus & { resources?: number; read?: string };

/**
 * Admission answers from the moment the process starts, before it waits on
 * Keto or the composition: an object applied while the IAM comes up must
 * still be checked, and the webhook refuses what it cannot check yet.
 * cert-manager renews the certificate in place, and the new one is read the
 * moment the kubelet swaps the mounted files.
 */
async function startWebhook(dir: string, context: AdmissionContext): Promise<FastifyInstance> {
  const read = () => ({ cert: readFileSync(join(dir, TLS.cert)), key: readFileSync(join(dir, TLS.key)) });
  const app = Fastify({ https: read(), bodyLimit: ADMISSION_BODY_LIMIT });
  app.post(WEBHOOK_PATH, async (req) => review(req.body, context));
  watch(dir, () => {
    try {
      (app.server as unknown as { setSecureContext: (options: ReturnType<typeof read>) => void }).setSecureContext(read());
    } catch (error) {
      console.error(JSON.stringify({ event: Logged.webhookCertReloadFailed, error: String(error) }));
    }
  });
  await app.listen({ port: WEBHOOK_PORT, host: ALL_INTERFACES });
  console.log(`Admission listening on port ${WEBHOOK_PORT}`);
  return app;
}

const listings: Record<Kind, () => Promise<DeploymentObject[]>> = {
  [Kind.role]: listRoles,
  [Kind.separation]: listSeparations,
  [Kind.resourceName]: listResourceNames,
  [Kind.document]: listDocuments as () => Promise<DeploymentObject[]>,
};
const stored: AdmissionContext['stored'] = async (kind) => listings[kind]();

/**
 * The single writer of grants and memberships: it composes the deployment's
 * routes and documents, applies its roles and separation rules in place,
 * answers admission, and checks and writes every assignment against one view
 * of roles, rules and memberships. With a lease, every replica composes and
 * answers admission, and only the one holding the lease writes.
 */
export async function start(options: StartOptions): Promise<void> {
  if (options.namespace === undefined) throw new Error('--namespace is required: the IAM composes in the cluster it runs in');
  const namespace = options.namespace;
  const keto = new KetoWriter(config.ketoWriteUrl, config.ketoReadUrl);
  const exclusive = serially();
  const started = new Date().toISOString();
  let elector: Elector | undefined;
  const leading = (): boolean => elector === undefined || elector.leader.self;

  let catalog: ServiceCatalog[] = [];
  let names: ResourceNames = {};
  let live: RolesFile = { roles: {} };
  let composed: Pick<Composed, 'model' | 'derivation' | 'rules'> | undefined;
  let applied: Applied | undefined;
  let pending: string[] = [];
  let told: { roles: RoleView[]; separations: RuleView[] } = { roles: [], separations: [] };
  let etag = '';
  let announced: string | undefined;

  const HISTORY = 'history.json';
  const kept = async (): Promise<History> => {
    const data = options.historyAs !== undefined ? await readConfigMap(namespace, options.historyAs) : undefined;
    return data?.[HISTORY] !== undefined ? (JSON.parse(data[HISTORY]) as History) : EMPTY;
  };
  let history: History = await kept();
  /** What a standby judges admission by: the kept history advanced over what it composed, written nowhere. */
  const judgedHistory = (): History => (leading() ? history : advance(history, catalog));
  /** What the change to a service's API means for the roles granting it, said where its route's owner looks. */
  const remember = async (tell: (service: string, message: string) => Promise<void>): Promise<void> => {
    if (!leading()) return;
    const next = advance(history, catalog);
    if (isDeepStrictEqual(next, history)) return;
    for (const [old, now] of Object.entries(next.renamed)) {
      if (history.renamed[old] !== now) await tell(serviceOf(old), `${old} is now ${now}; roles granting ${old} hold under ${now}`);
    }
    for (const gone of next.removed.filter((id) => !history.removed.includes(id))) {
      await tell(serviceOf(gone), `${gone} was removed; the grants of it are dropped`);
    }
    history = next;
    if (options.historyAs !== undefined) await publish(namespace, options.historyAs, { [HISTORY]: JSON.stringify(history) });
  };

  const provisioner = new Provisioner(keto, live, indexCatalogs(catalog), names);
  /** What each resource name lists, written onto its object whenever the leader lists it: on a pass, a provision, a check. */
  provisioner.onListed = (figures) => {
    if (!leading()) return;
    void (async () => {
      for (const object of await listResourceNames()) {
        const name = object.metadata?.name;
        const at = object.metadata?.namespace;
        const figure = name === undefined ? undefined : figures[name];
        if (figure === undefined || at === undefined) continue;
        const fields: ResourceNameStatus = { resources: figure.resources, ...(figure.read !== undefined ? { read: figure.read } : {}) };
        const shown = object.status as ResourceNameStatus | undefined;
        if (shown?.resources === fields.resources && shown?.read === fields.read) continue;
        await setStatus(AuthzResourceName, at, name!, fields);
      }
    })().catch((error) => console.error(JSON.stringify({ event: Logged.statusFailed, kind: Kind.resourceName, error: String(error) })));
  };
  let applying = false;

  const composition = (): Composition => ({
    catalog,
    resourceNames: servedNames(names, ownNames(catalog, options.servesAs)),
    roles: told.roles,
    separations: told.separations,
    pending,
    ...(applied !== undefined ? { applied } : {}),
    renamed: history.renamed,
    removed: history.removed,
    ...(options.servesAs !== undefined ? { servesAs: options.servesAs } : {}),
  });

  /** The ETag moves with the composition and with every start, so the API process reads it again after either. */
  const announce = async (): Promise<void> => {
    etag = tagOf(composition(), started);
    if (!ready || options.announceAs === undefined || etag === announced) return;
    await publish(namespace, options.announceAs, { [ANNOUNCED_ETAG]: etag });
    announced = etag;
  };
  const announceNow = () =>
    announce().catch((error) => console.error(JSON.stringify({ event: Logged.announceFailed, error: String(error) })));

  const kratos = options.kratosAdminUrl !== undefined ? new KratosAdmin(options.kratosAdminUrl) : undefined;
  /** Ends the sessions of whoever a write changed the permissions of; their next login writes what they hold then. */
  const revoke = async (affected: Affected): Promise<void> => {
    if (!affected.everyone && affected.subjects.length === 0) return;
    if (kratos === undefined) throw new Error('no Kratos admin URL to end sessions through');
    const subjects = affected.everyone ? (await kratos.list()).map((person) => person.id) : affected.subjects;
    for (const subject of subjects) await kratos.revokeSessions(subject);
    console.log(JSON.stringify({ event: Logged.sessionsRevoked, everyone: affected.everyone, subjects: subjects.length }));
  };

  let ready = false;
  const api = await controllerApi({
    keto,
    provisioner,
    exclusive,
    live: () => live,
    catalog: () => catalog,
    composition,
    etag: () => etag,
    composed: () => composed,
    applied: () => ready,
    ready: () => (leading() ? ready : composed !== undefined),
    leader: () => elector?.leader ?? { self: true },
    revoke,
  });
  await api.listen({ port: config.port, host: ALL_INTERFACES });
  console.log(`IAM controller listening on port ${config.port}, writing to ${config.ketoWriteUrl}`);

  const servers: FastifyInstance[] = [api];
  if (options.webhookCertDir !== undefined) {
    servers.push(
      await startWebhook(options.webhookCertDir, {
        get catalog() {
          return composed !== undefined ? catalog : undefined;
        },
        own: () => ownNames(catalog, options.servesAs),
        roleName: () => ownRoleName(catalog, options.servesAs),
        stored,
        held: () => heldInstances(keto),
        history: judgedHistory,
      }),
    );
  }

  const roles = new RoleSync({
    keto,
    objects: async () => {
      const [roleObjects, separations] = await Promise.all([listRoles(), listSeparations()]);
      return { roles: roleObjects, separations };
    },
    setStatus: (kind, at, name, status) => setStatus(kind === Kind.role ? AuthzRole : AuthzSeparation, at, name, status),
    history: () => history,
    owns: (object) =>
      object.metadata?.namespace === namespace &&
      Object.entries(MANAGED_BY).every(([key, value]) => object.metadata?.labels?.[key] === value),
    rewrite: (object, grants) =>
      applyRole({
        apiVersion: API_VERSION,
        kind: Kind.role,
        metadata: { name: object.metadata!.name!, namespace, labels: MANAGED_BY },
        spec: { ...object.spec, grants },
      } as unknown as AuthzRole),
    catalog: () => catalog,
    own: () => ownNames(catalog, options.servesAs),
    ready: (n) => waitForModel(keto, n),
    namespacesOf,
    exclusive,
    ...(options.adminEmail !== undefined && options.adminRole !== undefined && options.kratosAdminUrl !== undefined
      ? {
        admin: {
          email: options.adminEmail,
          role: options.adminRole,
          kratosAdminUrl: options.kratosAdminUrl,
          ...(options.kratosPublicUrl !== undefined ? { kratosPublicUrl: options.kratosPublicUrl } : {}),
          ...(options.adminPassword !== undefined ? { password: options.adminPassword } : {}),
        },
      }
      : {}),
    onApplied: (now, result, waiting, waitingRoles) => {
      provisioner.use(now, indexCatalogs(catalog), waitingRoles);
      live = now;
      applied = result;
      pending = waiting;
      for (const line of waiting) console.log(`WAITING  ${line}`);
      void revoke(result.affected).catch((error) =>
        console.error(JSON.stringify({ event: Logged.sessionsRevokeFailed, error: String(error) })),
      );
    },
    onTold: (roleViews, ruleViews) => {
      told = { roles: roleViews, separations: ruleViews };
      void announceNow();
      if (options.servesAs !== undefined) {
        const accepted = roleViews.filter((r) => r.ready.reason === Reason.accepted).map((r) => r.name);
        void exclusive(() => recordOwn(provisioner, ownResources(catalog, options.servesAs!, accepted))).catch((error) =>
          console.error(JSON.stringify({ event: Logged.ownResourcesFailed, error: String(error) })),
        );
      }
    },
  });

  const operator = new Operator({
    namespace,
    ...(options.publishAs !== undefined ? { publishAs: options.publishAs } : {}),
    ...(options.servesAs !== undefined ? { servesAs: options.servesAs } : {}),
    leading,
    count: (resourceName, current) => {
      provisioner.useNames(current);
      return provisioner.count(resourceName);
    },
    onAccepted: async (result, current) => {
      if (result.composition !== undefined) {
        catalog = result.composition.catalog;
        composed = {
          model: result.composition.model,
          derivation: result.composition.derivation,
          rules: result.composition.rules,
        };
      }
      names = current;
      provisioner.useNames(current);
      await remember((service, message) => operator.announceChange(service, message));
      console.log(JSON.stringify({ event: Logged.composed, services: catalog.map((c) => c.service), origins: result.origins }));
      if (applying) roles.schedule();
    },
  });
  const first = await operator.start();
  if (first.composition === undefined) {
    console.error(`nothing composed:\n  ${messagesOf(first.problems).join('\n  ')}`);
    process.exit(1);
  }

  await waitFor(`${config.ketoReadUrl}${ORY_READY}`, 'keto');
  await waitForModel(keto, ROLE_NAMESPACE);
  if (options.adminEmail !== undefined && options.kratosAdminUrl !== undefined) {
    if (options.adminRole === undefined) {
      throw new Error('--admin-role is required with --admin-email: the role is deployment configuration');
    }
    await waitFor(`${options.kratosAdminUrl}${ORY_READY}`, 'kratos');
  }

  let watcher: { close: () => void } | undefined;
  /**
   * What only the leader does: take up the history the last leader kept, write
   * back what it composed, apply the roles and announce.
   */
  const lead = async (): Promise<void> => {
    history = await kept();
    await operator.run();
    applying = true;
    await roles.run();
    watcher = await watchRoles(async () => roles.schedule());
    ready = true;
    console.log('IAM controller ready');
    await announceNow();
  };

  if (options.lease === undefined) {
    await lead();
  } else {
    const { identity, address } = replica();
    elector = new Elector({
      store: leaseStore(namespace, options.lease),
      identity,
      address,
      timing: leaseTiming(),
      onLeading: () =>
        void lead().catch((error) => {
          console.error(JSON.stringify({ event: Logged.leadFailed, error: String(error) }));
          process.exit(1);
        }),
      onLost: () => process.exit(1),
    });
    await elector.start();
    if (!leading()) console.log(JSON.stringify({ event: Logged.standingBy, lease: options.lease, leader: elector.leader }));
  }

  closeOnSignals(servers, async () => {
    await elector?.release().catch((error) => console.error(JSON.stringify({ event: Logged.leaseReleaseFailed, error: String(error) })));
    watcher?.close();
    operator.stop();
  });
}
