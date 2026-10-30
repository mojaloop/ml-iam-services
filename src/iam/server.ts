import { readFileSync } from 'node:fs';
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { join } from 'node:path';

import type { Context } from 'openapi-backend';
import { OpenAPIBackend } from 'openapi-backend';

import { accessRules, ResourceNames } from '../authzgen/compose';
import { ketoNamespace } from '../authzgen/keto-name';
import { ServiceCatalog } from '../authzgen/types';
import {
  AuthzResourceName,
  listDocuments,
  listResourceNames,
  listRoles,
  listSeparations,
  setStatus,
  watchRoles,
} from '../operator/cluster';
import { Operator } from '../operator/server';
import { AdmissionContext, review, WEBHOOK_PATH } from '../operator/webhook';
import { config } from './config';
import { KetoWriter } from './keto';
import { MEMBERS, parseInstance, ROLE_NAMESPACE } from './materialize';
import { ProvisionRequest } from './provision';
import { Assignment, Provisioner } from './provisioner';
import { Applied } from './reconcile';
import { RoleSync } from './role-sync';
import { indexCatalogs, openResourceNames, RolesFile } from './roles';
import { startSourceSync } from './source-sync';

/** What a deployment has to offer: the permissions services advertise, and the roles composed from them. */
export interface Offered {
  catalog: ServiceCatalog[];
  roles: RolesFile;
  /** The deployment's vocabulary, served verbatim to every consumer. */
  names?: ResourceNames;
  /** What this process last applied, absent until it has. */
  applied?: Applied;
  /** Roles and exclusions waiting for a service no route has brought yet. */
  pending?: string[];
  /** The composed rules, model and derivation, for the IAM's own callers. */
  composed?: { model: string; derivation: string; rules: Record<string, string> };
}

const readBody = async (req: IncomingMessage): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString();
};

const send = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
};

const sendText = (res: ServerResponse, body: string): void => {
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
};

/** What a handler answers; `text` serves plain, `body` serves JSON. */
interface Answer {
  status: number;
  body?: unknown;
  text?: string;
}

const one = (value: string | string[] | undefined): string | undefined =>
  Array.isArray(value) ? value[0] : value;

/**
 * The document routes and validates; each operation it declares maps to one
 * handler here, and a mismatch in either direction fails the start.
 */
export async function buildHandler(
  provisioner: Provisioner,
  offered: Offered = { catalog: [], roles: { roles: {} } },
  definition: string | object = join(__dirname, '..', '..', 'src', 'iam', 'api.yaml'),
) {
  const assignment = async (c: Context, granting: boolean): Promise<Answer> => {
    const subject = decodeURIComponent(one(c.request.params['subjectId'] as string | string[])!);
    const raw = c.request.requestBody as {
      role: string;
      resources?: Record<string, string>;
    };
    const parsed: Assignment = { role: raw.role, resources: raw.resources ?? {} };

    const problems = await provisioner.problemsWith(subject, parsed, granting);
    if (problems.length > 0) return { status: 422, body: { errors: problems } };

    const result = granting ? await provisioner.assign(subject, parsed) : await provisioner.unassign(subject, parsed);
    console.log(JSON.stringify({ event: granting ? 'assign' : 'unassign', subject, instance: result.instance }));
    return { status: 200, body: result };
  };

  const provision = async (c: Context, creating: boolean): Promise<Answer> => {
    const raw = c.request.requestBody as { resourceName: string; id: string };
    const parsed: ProvisionRequest = { resourceName: raw.resourceName, id: raw.id };
    try {
      if (creating) {
        const { problem } = await provisioner.provision(parsed);
        if (problem !== undefined) return { status: 422, body: { errors: [problem] } };
        console.log(JSON.stringify({ event: 'provision', resourceName: parsed.resourceName, id: parsed.id }));
        return { status: 200, body: { resourceName: parsed.resourceName, id: parsed.id } };
      }
      const result = await provisioner.deprovision(parsed);
      if (result.problem !== undefined) return { status: 422, body: { errors: [result.problem] } };
      console.log(
        JSON.stringify({
          event: 'deprovision',
          resourceName: parsed.resourceName,
          id: parsed.id,
          orphaned: result.orphaned,
        }),
      );
      return { status: 200, body: { orphaned: result.orphaned } };
    } catch (error) {
      console.error(JSON.stringify({ event: 'provision-error', error: String(error) }));
      return { status: 502, body: { error: String(error) } };
    }
  };

  const handlers: Record<string, (c: Context) => Answer | Promise<Answer>> = {
    getHealth: () => ({ status: 200, body: { status: 'ok' } }),
    getCatalog: () => ({ status: 200, body: offered.catalog }),
    getResourceNames: () => ({ status: 200, body: offered.names?.resourceNames ?? {} }),
    getKetoNamespaces: () => ({ status: 200, text: offered.composed?.model ?? '' }),
    getDerivation: () => ({ status: 200, text: offered.composed?.derivation ?? '' }),
    getAccessRules: () => ({ status: 200, text: accessRules(offered.composed?.rules ?? {}) }),
    /**
     * What this process is working from: which catalog, which roles, the
     * rules in force, and what applying them did. It answers "did the IAM
     * pick up the role I applied" and "which rule refused me", without anyone
     * reading a pod log.
     */
    getState: () => ({
      status: 200,
      body: {
        catalog: offered.catalog.map((c) => ({ service: c.service, permissions: c.permissions.length })),
        roles: Object.keys(offered.roles.roles),
        exclusions: offered.roles.exclusions ?? [],
        applied: offered.applied ?? null,
        pending: offered.pending ?? [],
      },
    }),
    getRoles: () => ({
      status: 200,
      body: Object.entries(offered.roles.roles).map(([name, role]) => ({
        name,
        open: openResourceNames(role, indexCatalogs(offered.catalog)),
        grants: role.grants,
      })),
    }),
    getResources: async (c) => ({
      status: 200,
      body: await provisioner.resources(one(c.request.query['resourceName'])),
    }),
    getSubjectAssignments: async (c) => ({
      status: 200,
      body: await provisioner.assignments(decodeURIComponent(one(c.request.params['subjectId'] as string | string[])!)),
    }),
    assignSubjectRole: (c) => assignment(c, true),
    unassignSubjectRole: (c) => assignment(c, false),
    provisionResource: (c) => provision(c, true),
    deprovisionResource: (c) => provision(c, false),
  };

  const api = new OpenAPIBackend({ definition: definition as string });
  api.register({
    notFound: (): Answer => ({ status: 404, body: { error: 'Not found' } }),
    methodNotAllowed: (): Answer => ({ status: 405, body: { error: 'Method not allowed' } }),
    validationFail: (c): Answer => ({ status: 400, body: { errors: c.validation.errors } }),
  });
  for (const [operationId, handle] of Object.entries(handlers)) api.register(operationId, handle);
  await api.init();

  const declared = api.router
    .getOperations()
    .map((operation) => operation.operationId)
    .filter((id): id is string => id !== undefined);
  const handled = Object.keys(handlers);
  const unhandled = declared.filter((id) => !handled.includes(id));
  const undeclared = handled.filter((id) => !declared.includes(id));
  if (unhandled.length > 0 || undeclared.length > 0) {
    throw new Error(
      `the document and the handlers disagree:` +
        (unhandled.length > 0 ? ` no handler for [${unhandled.join(', ')}]` : '') +
        (undeclared.length > 0 ? ` no operation for [${undeclared.join(', ')}]` : ''),
    );
  }

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', 'http://iam');
    const raw = await readBody(req);
    let body: unknown;
    if (raw !== '') {
      try {
        body = JSON.parse(raw);
      } catch {
        body = raw;
      }
    }
    const answer = (await api.handleRequest({
      method: req.method ?? 'GET',
      path: url.pathname,
      query: url.search,
      body,
      headers: req.headers as Record<string, string | string[]>,
    })) as Answer;
    if (answer.text !== undefined) return sendText(res, answer.text);
    return send(res, answer.status, answer.body);
  };
}

/** Every Keto namespace applying these roles writes into. */
const namespacesOf = (file: RolesFile): string[] => [
  ROLE_NAMESPACE,
  ...new Set(
    Object.values(file.roles).flatMap((role) => role.grants.map((g) => ketoNamespace(g.permission.split('.')[0]!))),
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

/** Keto and Kratos come up alongside this, so first refusal is not a verdict. */
async function waitFor(url: string, name: string): Promise<void> {
  for (;;) {
    try {
      await fetch(url);
      return;
    } catch {
      console.log(`waiting for ${name} at ${url}`);
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
}

export interface StartOptions {
  adminEmail?: string;
  /** Without one, a created admin is invited by email to set a password. */
  adminPassword?: string;
  adminRole?: string;
  kratosAdminUrl?: string;
  kratosPublicUrl?: string;
  /** The namespace the composition is published into. */
  namespace?: string;
  /** The ConfigMap the composed rules and catalog are published as. */
  publishAs?: string;
  /** A directory holding tls.crt and tls.key, to answer admission over HTTPS. */
  webhookCertDir?: string;
}

const WEBHOOK_PORT = 9443;
/** cert-manager renews the certificate in place; the server picks it up without a restart. */
const CERT_RELOAD_MS = 60_000;

/**
 * Admission answers from the moment the process starts, before it waits on
 * Keto or the composition: an object applied while the IAM comes up must
 * still be checked, and the webhook refuses what it cannot check yet.
 */
function startWebhook(dir: string, context: AdmissionContext): void {
  const read = () => ({ cert: readFileSync(join(dir, 'tls.crt')), key: readFileSync(join(dir, 'tls.key')) });
  const server = createHttpsServer(read(), (req, res) => {
    if (req.method !== 'POST' || req.url?.split('?')[0] !== WEBHOOK_PATH) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    readBody(req)
      .then((raw) => review(JSON.parse(raw), context))
      .then((answer) => send(res, 200, answer))
      .catch((error) => send(res, 400, { error: String(error) }));
  });
  setInterval(() => {
    try {
      server.setSecureContext(read());
    } catch (error) {
      console.error(JSON.stringify({ event: 'webhook-cert-reload-failed', error: String(error) }));
    }
  }, CERT_RELOAD_MS).unref();
  server.listen(WEBHOOK_PORT, () => console.log(`Admission listening on port ${WEBHOOK_PORT}`));
}

const stored: AdmissionContext['stored'] = async (kind) =>
  kind === 'AuthzRole'
    ? listRoles()
    : kind === 'AuthzSeparation'
      ? listSeparations()
      : kind === 'AuthzResourceName'
        ? listResourceNames()
        : listDocuments();

/**
 * The deployment's roles, separation rules and resource names are objects
 * the IAM watches, so a change to any of them is applied in place, and each
 * object says what became of it.
 */
export async function start(options: StartOptions): Promise<void> {
  if (options.namespace === undefined) throw new Error('--namespace is required: the IAM composes in the cluster it runs in');
  const keto = new KetoWriter(config.ketoWriteUrl, config.ketoReadUrl);
  const offered: Offered = { catalog: [], roles: { roles: {} }, names: {} };
  const provisioner = new Provisioner(keto, offered.roles, indexCatalogs(offered.catalog), offered.names);
  let composed = false;
  let applying = false;
  let sync: { stop: () => void } | undefined;
  let syncedAs: string | undefined;
  const lastSync = new Map<string, string>();

  const holders = async (role: string): Promise<number> =>
    new Set(
      (await keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS }))
        .filter((t) => parseInstance(t.object).role === role && t.subject_id !== undefined)
        .map((t) => t.subject_id),
    ).size;

  if (options.webhookCertDir !== undefined) {
    startWebhook(options.webhookCertDir, {
      get catalog() {
        return composed ? offered.catalog : undefined;
      },
      stored,
      holders,
    });
  }

  /** How many resources of each name exist, and when its source was last read. */
  const reportCounts = async (): Promise<void> => {
    for (const object of await listResourceNames()) {
      const name = object.metadata?.name;
      const namespace = object.metadata?.namespace;
      if (name === undefined || namespace === undefined) continue;
      const count = (await provisioner.resources(name)).length;
      const at = lastSync.get(name);
      if (object.status?.['resources'] === count && (at === undefined || object.status?.['lastSync'] === at)) continue;
      await setStatus(AuthzResourceName, namespace, name, { resources: count, ...(at !== undefined ? { lastSync: at } : {}) }).catch(
        (error) => console.error(JSON.stringify({ event: 'status-failed', object: `AuthzResourceName/${namespace}/${name}`, error: String(error) })),
      );
    }
  };

  /** The sources the resource names declare, read again whenever the names change. */
  const syncSources = async (names: ResourceNames): Promise<void> => {
    const signature = JSON.stringify(names);
    if (signature === syncedAs) return;
    syncedAs = signature;
    sync?.stop();
    sync = await startSourceSync({
      names,
      keto,
      intervalMs: config.sourceSyncSeconds * 1000,
      onSynced: (resourceName, at) => {
        lastSync.set(resourceName, at);
        void reportCounts();
      },
    }).catch((error) => {
      console.error(JSON.stringify({ event: 'source-sync-refused', error: String(error) }));
      return undefined;
    });
  };

  const roles = new RoleSync({
    keto,
    catalog: () => offered.catalog,
    ready: (namespace) => waitForModel(keto, namespace),
    namespacesOf,
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
    onApplied: (live, applied, pending) => {
      provisioner.use(live, indexCatalogs(offered.catalog));
      offered.roles = live;
      offered.applied = applied;
      offered.pending = pending;
      for (const line of pending) console.log(`WAITING  ${line}`);
    },
  });

  const operator = new Operator({
    namespace: options.namespace,
    ...(options.publishAs !== undefined ? { publishAs: options.publishAs } : {}),
    onAccepted: async (result, names) => {
      if (result.composition !== undefined) {
        offered.catalog = result.composition.catalog;
        offered.composed = {
          model: result.composition.model,
          derivation: result.composition.derivation,
          rules: result.composition.rules,
        };
      }
      offered.names = names;
      composed = true;
      provisioner.useNames(names);
      console.log(JSON.stringify({ event: 'composed', services: offered.catalog.map((c) => c.service), origins: result.origins }));
      if (applying) {
        await syncSources(names);
        roles.schedule();
      }
    },
  });
  const first = await operator.start();
  if (first.composition === undefined) {
    console.error(`nothing composed:\n  ${first.problems.join('\n  ')}`);
    process.exit(1);
  }

  await waitFor(`${config.ketoReadUrl}/health/ready`, 'keto');
  await waitForModel(keto, ROLE_NAMESPACE);
  if (options.adminEmail !== undefined && options.kratosAdminUrl !== undefined) {
    if (options.adminRole === undefined) {
      throw new Error('--admin-role is required with --admin-email: the role is deployment configuration');
    }
    await waitFor(`${options.kratosAdminUrl}/health/ready`, 'kratos');
  }

  applying = true;
  await roles.run();
  const watcher = await watchRoles(async () => roles.schedule());
  await syncSources(offered.names ?? {});
  await reportCounts();

  const handler = await buildHandler(provisioner, offered);
  const server = createServer((req, res) => {
    handler(req, res).catch((error) => {
      console.error('Unhandled error:', error);
      send(res, 500, { error: 'Internal server error' });
    });
  });

  server.listen(config.port, () => {
    console.log(`IAM provisioning listening on port ${config.port}`);
    console.log(`Writing to: ${config.ketoWriteUrl}`);
  });

  const shutdown = (): void => {
    sync?.stop();
    watcher.close();
    operator.stop();
    server.close(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
