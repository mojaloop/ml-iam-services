import { StatusCodes } from 'http-status-codes';

import { ResourceName, sourceProblems } from '../authzgen/compose';
import { derive } from '../authzgen/derive';
import { serviceOf } from '../authzgen/permission';
import { messagesOf } from '../authzgen/problem';
import { ServiceCatalog } from '../authzgen/types';
import { broken, Exclusion, holdingsOf, roleBreaks, ruleProblems, Within } from '../iam/exclusions';
import { History, resolveRole } from '../iam/history';
import { Kind } from '../iam/kinds';
import { DeploymentObject, exclusionOf, idOf, roleOf, RoleSpec, SeparationSpec } from '../iam/objects';
import { indexCatalogs, namedByProblem, rolesNaming, validateRoles } from '../iam/roles';
import { AuthzDocumentResource, fromResource } from './sources';

/**
 * Admission for the IAM's kinds: the same checks the IAM applies, run when an
 * object is written, so one that would be refused is refused with the reason
 * instead of stored. What names a service the deployment has not composed
 * yet is admitted, and waits for it.
 */

export const WEBHOOK_PATH = '/validate';

const REVIEW = { apiVersion: 'admission.k8s.io/v1', kind: 'AdmissionReview' } as const;

/** What a reviewed request does to its object; one that removes it carries it as the old one. */
export const AdmissionOperation = { create: 'CREATE', update: 'UPDATE', delete: 'DELETE' } as const;

/** The prefix a document is derived under when admission only checks that it derives, before any route names its own. */
const DOCUMENT_PREFIX = 'document';

interface Incoming extends DeploymentObject {
  kind?: string;
  spec?: Record<string, unknown>;
}

interface AdmissionReview {
  apiVersion?: string;
  kind?: string;
  request?: {
    uid?: string;
    operation?: string;
    kind?: { kind?: string };
    object?: Incoming;
    oldObject?: Incoming;
  };
}

/** What admission checks against: the IAM's current composition and the objects already stored. */
export interface AdmissionContext {
  /** Absent until the IAM has composed once. */
  catalog?: ServiceCatalog[];
  /** The IAM's own resource names, the only ones a grant names by id. */
  own: () => ReadonlySet<string>;
  /** The resource name roles go by, which a grant names one under. */
  roleName: () => string | undefined;
  /** Every stored object of a kind, for names held elsewhere and the rules a role meets. */
  stored: (kind: Kind) => Promise<DeploymentObject[]>;
  /** Every role instance each subject holds, as the graph has it. */
  held: () => Promise<Map<string, Array<{ role: string; resources: Record<string, string> }>>>;
  /** What became of the permissions services no longer offer. */
  history: () => History;
}

const services = (catalog: ServiceCatalog[]) => new Set(catalog.map((c) => c.service));

const composedPermissions = (ids: string[], catalog: ServiceCatalog[]): string[] => {
  const composed = services(catalog);
  return ids.filter((id) => composed.has(serviceOf(id)));
};

async function roleProblems(
  object: Incoming,
  old: Incoming | undefined,
  context: AdmissionContext,
  warnings: string[],
): Promise<string[]> {
  const catalog = context.catalog!;
  const name = object.metadata?.name ?? '';
  const index = indexCatalogs(catalog);
  const resolved = resolveRole(roleOf(object.spec as RoleSpec), context.history(), index);
  warnings.push(...resolved.warnings.map((w) => `${name}: ${w}`));
  const role = resolved.role;
  const composed = new Set(composedPermissions(role.grants.map((g) => g.permission), catalog));
  const checked = { ...role, grants: role.grants.filter((g) => composed.has(g.permission)) };
  const rules: Exclusion[] = (await context.stored(Kind.separation)).map((s) =>
    exclusionOf(s.metadata?.name ?? '', (s as Incoming).spec as SeparationSpec),
  );

  const problems: string[] = [];
  if (checked.grants.length > 0) {
    problems.push(...validateRoles({ roles: { [name]: checked }, exclusions: rules }, index, context.own()));
  }
  for (const problem of roleBreaks(checked, rules, index)) problems.push(`${name}: its grants span ${problem}`);

  const holding = [...(await context.held())].filter(([, instances]) => instances.some((i) => i.role === name));
  if (role.heldBy !== undefined && old !== undefined && (old.spec as RoleSpec | undefined)?.heldBy === undefined && holding.length > 0) {
    problems.push(`${name}: ${holding.length} subjects are assigned it; a role every subject holds is assigned to nobody`);
  }
  if (old !== undefined && rules.length > 0 && holding.length > 0) {
    const roles = Object.fromEntries(
      (await context.stored(Kind.role)).map((o) => [o.metadata?.name ?? '', roleOf((o as Incoming).spec as RoleSpec)]),
    );
    const file = { roles: { ...roles, [name]: checked } };
    for (const [subject, instances] of holding) {
      for (const breach of broken(holdingsOf(file, instances), rules, index)) {
        problems.push(`${name}: the change would leave ${subject}, who holds it, breaking ${breach}`);
      }
    }
  }
  return [...new Set(problems)];
}

async function separationProblems(object: Incoming, context: AdmissionContext): Promise<string[]> {
  const catalog = context.catalog!;
  const rule = exclusionOf(object.metadata?.name ?? '', object.spec as SeparationSpec);
  const problems = ruleProblems(rule, indexCatalogs(catalog), services(catalog));
  if (rule.within === Within.resource && rule.resourceName !== undefined) {
    const declared = (await context.stored(Kind.resourceName)).map((o) => o.metadata?.name);
    if (!declared.includes(rule.resourceName)) problems.push(`${rule.name}: no resource name called ${rule.resourceName}`);
  }
  return problems;
}

function resourceNameProblems(object: Incoming, context: AdmissionContext): string[] {
  const label = object.metadata?.name ?? '';
  const spec = object.spec as unknown as ResourceName;
  const problems = messagesOf(sourceProblems(label, spec));
  const byService = new Map(context.catalog!.map((c) => [c.service, new Set(c.resourceTypes)]));
  for (const member of spec.members ?? []) {
    const types = byService.get(member.service);
    if (types !== undefined && !types.has(member.type)) {
      problems.push(`resource name ${label} lists ${member.service}.${member.type}, which ${member.service} is not about`);
    }
  }
  return problems;
}

/** Another object of the same kind holding this name. */
async function heldElsewhere(kind: Kind, object: Incoming, context: AdmissionContext): Promise<string | undefined> {
  const owner = (await context.stored(kind)).find(
    (o) => o.metadata?.name === object.metadata?.name && o.metadata?.uid !== object.metadata?.uid,
  );
  return owner === undefined
    ? undefined
    : `${object.metadata?.name} is already defined by ${idOf(kind, owner)}; a name is unique across the cluster`;
}

export async function review(
  body: unknown,
  context?: AdmissionContext,
): Promise<AdmissionReview & { response: object }> {
  const request = (body as AdmissionReview)?.request;
  const uid = request?.uid ?? '';
  const warnings: string[] = [];
  const answer = (allowed: boolean, message?: string) => ({
    ...REVIEW,
    response: {
      uid,
      allowed,
      ...(message !== undefined ? { status: { code: StatusCodes.UNPROCESSABLE_ENTITY, message } } : {}),
      ...(warnings.length > 0 ? { warnings } : {}),
    },
  });

  if (request?.operation === AdmissionOperation.delete) {
    const gone = request.oldObject;
    if (gone === undefined) return answer(false, 'the review carries no object');
    if (request.kind?.kind !== Kind.role) return answer(true);
    if (context === undefined || context.catalog === undefined) {
      return answer(false, `${idOf(Kind.role, gone)}: the IAM has composed nothing yet to check it against`);
    }
    const name = gone.metadata?.name ?? '';
    const roles = Object.fromEntries(
      (await context.stored(Kind.role)).map((o) => [o.metadata?.name ?? '', roleOf((o as Incoming).spec as RoleSpec)]),
    );
    const naming = rolesNaming(name, roles, context.roleName());
    return naming.length === 0 ? answer(true) : answer(false, `${idOf(Kind.role, gone)}: ${namedByProblem(name, naming)}`);
  }

  const object = request?.object;
  if (object === undefined) return answer(false, 'the review carries no object');
  const kind = (request?.kind?.kind ?? object.kind ?? Kind.document) as Kind;

  try {
    if (kind === Kind.document) {
      derive(await fromResource(object as AuthzDocumentResource), DOCUMENT_PREFIX);
      return answer(true);
    }
    if (context === undefined || context.catalog === undefined) {
      return answer(false, `${idOf(kind, object)}: the IAM has composed nothing yet to check it against`);
    }
    const elsewhere = await heldElsewhere(kind, object, context);
    if (elsewhere !== undefined) return answer(false, `${idOf(kind, object)}: ${elsewhere}`);

    const problems =
      kind === Kind.role
        ? await roleProblems(object, request?.oldObject, context, warnings)
        : kind === Kind.separation
          ? await separationProblems(object, context)
          : resourceNameProblems(object, context);
    return problems.length === 0 ? answer(true) : answer(false, `${idOf(kind, object)}:\n  ${problems.join('\n  ')}`);
  } catch (error) {
    return answer(false, (error as Error).message);
  }
}
