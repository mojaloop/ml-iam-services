import { readFile } from 'node:fs/promises';

import { stringify } from 'yaml';

import { ResourceNames } from './compose';
import { derive } from './derive';
import { emitModel } from './emit-model';
import { emitRules, Serving } from './emit-rules';
import { ketoNamespace } from './keto-name';
import { Permission, ServiceBundle, ServiceCatalog } from './types';

export * from './compose';
export { derive } from './derive';
export { emitModel } from './emit-model';
export { clientPath, emitRules, Mount, reachesSubtree, Rewrite, Serving } from './emit-rules';
export { ketoNamespace, PREFIX } from './keto-name';
export * from './types';

/**
 * Reads a document, as text or as an already parsed object: validated as
 * OpenAPI 3.1 or later and with every `$ref` resolved, so a document split
 * across files derives the same as one written inline, and one that is not
 * OpenAPI at all stops the rollout here.
 *
 * The parser answers what OpenAPI means; what `x-authz` means is read from
 * the package a service's own guard reads it with, so the deploy-time
 * conclusion and the runtime one cannot differ.
 */
export async function readSpec(input: string | Record<string, unknown>, origin: string): Promise<unknown> {
  const { validate, dereference } = await import('@scalar/openapi-parser');
  const { valid, errors, schema, version } = await validate(input, { throwOnError: false });

  if (!valid || schema === undefined) {
    const reasons = (errors ?? []).map((e) => e.message ?? String(e)).join('; ');
    throw new Error(`${origin}: is not a valid OpenAPI document${reasons ? `: ${reasons}` : ''}`);
  }
  if (!/^3\.[1-9]\d*\./.test(`${String(version)}.`)) {
    throw new Error(`${origin}: OpenAPI ${version} is not supported; the document must declare 3.1 or later`);
  }

  const resolved = dereference(schema);
  if (resolved.schema === undefined) {
    throw new Error(`${origin}: has references that do not resolve`);
  }
  return resolved.schema;
}

/** Reads a document from disk. */
export const loadSpec = async (ref: string): Promise<unknown> => readSpec(await readFile(ref, 'utf8'), ref);

/**
 * The catalog the role UI reads: one entry per permission, carrying the text
 * a human sees and the resource slots a role must bind.
 */
export function emitCatalog(bundle: ServiceBundle): ServiceCatalog {
  return {
    service: bundle.service,
    namespace: ketoNamespace(bundle.service),
    title: bundle.title,
    basePath: bundle.basePath,
    resourceTypes: bundle.resourceTypes,
    permissions: bundle.permissions.map((p) => ({
      id: p.id,
      relation: p.name,
      operationId: p.operationId,
      summary: p.summary,
      deprecated: p.deprecated,
      method: p.method,
      path: p.path,
      scopedBy: p.scopedBy.map((r) => r.type),
      bound: p.scopedBy.filter((r) => r.captureIndex !== undefined).map((r) => r.type),
      resourceNames: Object.fromEntries(
        p.scopedBy.filter((r) => r.resourceName !== undefined).map((r) => [r.type, r.resourceName!]),
      ),
    })),
  };
}

/**
 * The derivation table: what the generator concluded about every operation,
 * reviewed once per service and diffed on every build, so a wrong derivation
 * shows up as a changed line.
 */
export function emitDerivation(bundle: ServiceBundle): string {
  const rows = bundle.permissions.map((p) => {
    const bound = p.scopedBy.filter((r) => r.captureIndex !== undefined);
    const checks =
      bound.length === 0 ? '__self__' : bound.map((r) => `${r.type}/{${r.param}}`).join(' + ');
    const scope = `scope:${p.scopedBy.map((r) => r.type).join(',') || 'none'}`;
    return [p.method.padEnd(6), p.path.padEnd(52), p.id.padEnd(38), checks.padEnd(28), scope].join(' ');
  });
  const header = [
    `# ${bundle.service} — derived authorization surface`,
    `# ${bundle.permissions.length} operations, resource types: ${bundle.resourceTypes.join(', ') || 'none'}`,
    '',
  ];
  return [...header, ...rows, ''].join('\n');
}

export interface GenerateResult {
  bundle: ServiceBundle;
  rules: string;
  model: string;
  catalog: string;
  derivation: string;
}

/**
 * Stamps every scoped type with the resource name the deployment declared
 * for it. The rules check and the grants bind the resource name, so a scoped
 * type outside the vocabulary cannot generate.
 */
function nameScopes(bundle: ServiceBundle, names: ResourceNames): void {
  const byMember = new Map<string, string>();
  for (const [resourceName, declared] of Object.entries(names.resourceNames ?? {})) {
    for (const member of declared.members) byMember.set(`${member.service}.${member.type}`, resourceName);
  }
  for (const permission of bundle.permissions) {
    for (const arg of permission.scopedBy) {
      const resourceName = byMember.get(`${bundle.service}.${arg.type}`);
      if (resourceName === undefined) {
        throw new Error(
          `${bundle.service} is about ${arg.type}, and no resource name lists ${bundle.service}.${arg.type}`,
        );
      }
      arg.resourceName = resourceName;
    }
  }
}

/**
 * @param reachable  keeps the operations a route can actually send, given the
 *                   service's base path; everything else gets no rule
 */
export function generate(
  doc: unknown,
  service: string,
  serving: Serving = {},
  names: ResourceNames = {},
  reachable?: (permission: Permission, basePath: string) => boolean,
): GenerateResult {
  const serviceBundle = derive(doc, service);
  nameScopes(serviceBundle, names);
  if (reachable !== undefined) {
    serviceBundle.permissions = serviceBundle.permissions.filter((p) => reachable(p, serviceBundle.basePath));
  }
  return {
    bundle: serviceBundle,
    rules: stringify(emitRules(serviceBundle, serving), { lineWidth: 0 }),
    model: emitModel(serviceBundle),
    catalog: JSON.stringify(emitCatalog(serviceBundle), null, 2),
    derivation: emitDerivation(serviceBundle),
  };
}
