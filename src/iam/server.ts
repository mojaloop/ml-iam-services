import { readFileSync } from 'node:fs';
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { join } from 'node:path';

import type { Context } from 'openapi-backend';
import { OpenAPIBackend } from 'openapi-backend';
import { parse as parseYaml } from 'yaml';

import { accessRules, Migrations, ResourceNames } from '../authzgen/compose';
import { ServiceCatalog } from '../authzgen/types';
import { Operator } from '../operator/server';
import { config } from './config';
import { KetoWriter } from './keto';
import { ROLE_NAMESPACE } from './materialize';
import { ProvisionRequest } from './provision';
import { Assignment, Provisioner } from './provisioner';
import { Applied, applyRoles, report } from './reconcile';
import { indexCatalogs, openResourceNames, RolesFile, validateRoles } from './roles';
import { startSourceSync } from './source-sync';

/** What a deployment has to offer: the permissions services advertise, and the roles composed from them. */
export interface Offered {
  catalog: ServiceCatalog[];
  roles: RolesFile;
  /** The deployment's vocabulary, served verbatim to every consumer. */
  names?: ResourceNames;
  /** What this process applied when it started, absent until it has. */
  applied?: Applied;
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
     * rules in force, and what applying them did. It answers "did this pod
     * pick up the file I edited" and "which rule refused me", without anyone
     * reading a pod log.
     */
    getState: () => ({
      status: 200,
      body: {
        catalog: offered.catalog.map((c) => ({ service: c.service, permissions: c.permissions.length })),
        roles: Object.keys(offered.roles.roles),
        exclusions: offered.roles.exclusions ?? [],
        applied: offered.applied ?? null,
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
  roles: string;
  /** Composed catalogs to read, for a run with no namespace to compose in. */
  catalog?: string[];
  migrations?: string;
  adminEmail?: string;
  /** Without one, a created admin is invited by email to set a password. */
  adminPassword?: string;
  adminRole?: string;
  kratosAdminUrl?: string;
  kratosPublicUrl?: string;
  /** The namespace whose AuthzDocuments this reconciles, when it runs in one. */
  namespace?: string;
  /** A registry file the chart mounted, composed alongside those documents. */
  registry?: string;
  /** The deployment's names for one thing across services. */
  resourceNames?: string;
  /** The ConfigMap the composed rules and catalog are published as. */
  publishAs?: string;
}

/** Reads a composed catalog: every service of a deployment, per file. */
export const readCatalogs = (paths: string[]): ServiceCatalog[] =>
  paths.flatMap((p) => JSON.parse(readFileSync(p, 'utf8')) as ServiceCatalog[]);

/**
 * The roles arrive as configuration, so the moment this starts is also the
 * moment they changed: applying them is the first thing it does, and it does
 * not answer a request until it has.
 */
export async function start(options: StartOptions): Promise<void> {
  const read = <T>(path: string): T => JSON.parse(readFileSync(path, 'utf8')) as T;
  const roles = read<RolesFile>(options.roles);

  // Keto's namespaces and the gateway's rules are published out of the
  // composition, and are what those two read to start, so nothing below can
  // wait on Keto until it exists. Its catalog is what the roles are checked
  // against.
  const names: ResourceNames =
    options.resourceNames !== undefined
      ? (parseYaml(readFileSync(options.resourceNames, 'utf8')) as ResourceNames)
      : {};

  const offered: Offered = { catalog: [], roles, names };
  let operator: Operator | undefined;
  let recomposed = Promise.resolve();
  let composition: () => void = () => {};
  const awaitComposition = (): void => {
    recomposed = new Promise<void>((resolve) => {
      composition = resolve;
    });
  };

  if (options.namespace !== undefined) {
    operator = new Operator({
      namespace: options.namespace,
      names,
      ...(options.registry !== undefined ? { registry: options.registry } : {}),
      ...(options.publishAs !== undefined ? { publishAs: options.publishAs } : {}),
      onAccepted: (result) => {
        if (result.composition !== undefined) {
          offered.catalog = result.composition.catalog;
          offered.composed = {
            model: result.composition.model,
            derivation: result.composition.derivation,
            rules: result.composition.rules,
          };
        }
        const services = result.composition?.catalog.map((c) => c.service) ?? [];
        console.log(JSON.stringify({ event: 'composed', services, origins: result.origins }));
        composition();
      },
    });
    const first = await operator.start();
    if (first.composition === undefined) {
      console.error(`nothing composed:\n  ${first.problems.join('\n  ')}`);
      process.exit(1);
    }
  } else {
    offered.catalog = readCatalogs(options.catalog ?? []);
  }

  // The roles must validate against the catalog before anything is applied or
  // served: staying unready leaves the previous pod serving the previous
  // policy. Documents arrive as cluster resources, so a catalog can complete
  // on a later composition — readiness holds until one covers the roles. A
  // catalog read from files is the whole of it, so there a mismatch is fatal.
  awaitComposition();
  let index = indexCatalogs(offered.catalog);
  let problems = validateRoles(roles, index);
  while (problems.length > 0) {
    if (operator === undefined) {
      console.error(`${options.roles} does not match the catalog:\n  ${problems.join('\n  ')}`);
      process.exit(1);
    }
    console.error(
      `${options.roles} does not match the catalog, holding readiness for the documents that declare it:\n  ${problems.join('\n  ')}`,
    );
    await recomposed;
    awaitComposition();
    index = indexCatalogs(offered.catalog);
    problems = validateRoles(roles, index);
  }

  const keto = new KetoWriter(config.ketoWriteUrl, config.ketoReadUrl);
  await waitFor(`${config.ketoReadUrl}/health/ready`, 'keto');
  await waitForModel(keto, ROLE_NAMESPACE);
  if (options.adminEmail !== undefined && options.kratosAdminUrl !== undefined) {
    if (options.adminRole === undefined) {
      throw new Error('--admin-role is required with --admin-email: the role is deployment configuration');
    }
    await waitFor(`${options.kratosAdminUrl}/health/ready`, 'kratos');
  }

  const applied = await applyRoles(keto, roles, index, {
    ...(options.migrations !== undefined ? { migrations: read<Migrations>(options.migrations) } : {}),
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
  });
  for (const line of report(applied)) console.log(line);

  const sync = await startSourceSync({
    names,
    keto,
    intervalMs: config.sourceSyncSeconds * 1000,
  });

  const provisioner = new Provisioner(keto, roles, index, names);
  offered.applied = applied;
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
    sync.stop();
    operator?.stop();
    server.close(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
