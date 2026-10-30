import { ResourceName, sourceProblems } from '../authzgen/compose';
import { derive } from '../authzgen/derive';
import { ServiceCatalog } from '../authzgen/types';
import { Exclusion, roleBreaks, ruleProblems } from '../iam/exclusions';
import { DeploymentObject, exclusionOf, HELD_BY_UNAPPLIED, idOf, roleOf, RoleSpec, SeparationSpec } from '../iam/objects';
import { indexCatalogs, validateRoles } from '../iam/roles';
import { AuthzDocumentResource, fromResource } from './sources';

/**
 * Admission for the IAM's kinds: the same checks the IAM applies, run when an
 * object is written, so one that would be refused is refused with the reason
 * instead of stored. What names a service the deployment has not composed
 * yet is admitted, and waits for it.
 */

export const WEBHOOK_PATH = '/validate';

type Kind = 'AuthzDocument' | 'AuthzRole' | 'AuthzSeparation' | 'AuthzResourceName';

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
  /** Every stored object of a kind, for names held elsewhere and the rules a role meets. */
  stored: (kind: Kind) => Promise<DeploymentObject[]>;
  /** How many subjects hold a role, to refuse making a held role every subject's. */
  holders: (role: string) => Promise<number>;
}

const services = (catalog: ServiceCatalog[]) => new Set(catalog.map((c) => c.service));

const composedPermissions = (ids: string[], catalog: ServiceCatalog[]): string[] => {
  const composed = services(catalog);
  return ids.filter((id) => composed.has(id.split('.')[0]!));
};

async function roleProblems(object: Incoming, old: Incoming | undefined, context: AdmissionContext): Promise<string[]> {
  const catalog = context.catalog!;
  const name = object.metadata?.name ?? '';
  const role = roleOf(object.spec as RoleSpec);
  const index = indexCatalogs(catalog);
  const composed = new Set(composedPermissions(role.grants.map((g) => g.permission), catalog));
  const checked = { ...role, grants: role.grants.filter((g) => composed.has(g.permission)) };
  const rules: Exclusion[] = (await context.stored('AuthzSeparation')).map((s) =>
    exclusionOf(s.metadata?.name ?? '', (s as Incoming).spec as SeparationSpec),
  );

  const problems: string[] = [];
  if (role.heldBy !== undefined) problems.push(`${name}: ${HELD_BY_UNAPPLIED}`);
  if (checked.grants.length > 0) {
    problems.push(...validateRoles({ roles: { [name]: checked }, exclusions: rules }, index));
  }
  for (const problem of roleBreaks(checked, rules, index)) problems.push(`${name}: its grants span ${problem}`);
  if (role.heldBy !== undefined && old !== undefined && (old.spec as RoleSpec | undefined)?.heldBy === undefined) {
    const held = await context.holders(name);
    if (held > 0) problems.push(`${name}: ${held} subjects are assigned it; a role every subject holds is assigned to nobody`);
  }
  return [...new Set(problems)];
}

async function separationProblems(object: Incoming, context: AdmissionContext): Promise<string[]> {
  const catalog = context.catalog!;
  const rule = exclusionOf(object.metadata?.name ?? '', object.spec as SeparationSpec);
  const problems = ruleProblems(rule, indexCatalogs(catalog), services(catalog));
  if (rule.within === 'resource' && rule.resourceName !== undefined) {
    const declared = (await context.stored('AuthzResourceName')).map((o) => o.metadata?.name);
    if (!declared.includes(rule.resourceName)) problems.push(`${rule.name}: no resource name called ${rule.resourceName}`);
  }
  return problems;
}

function resourceNameProblems(object: Incoming, context: AdmissionContext): string[] {
  const label = object.metadata?.name ?? '';
  const spec = object.spec as unknown as ResourceName;
  const problems = sourceProblems(label, spec);
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
  const answer = (allowed: boolean, message?: string) => ({
    apiVersion: 'admission.k8s.io/v1',
    kind: 'AdmissionReview',
    response: { uid, allowed, ...(message !== undefined ? { status: { code: 422, message } } : {}) },
  });

  const object = request?.object;
  if (object === undefined) return answer(false, 'the review carries no object');
  const kind = (request?.kind?.kind ?? object.kind ?? 'AuthzDocument') as Kind;

  try {
    if (kind === 'AuthzDocument') {
      derive(await fromResource(object as AuthzDocumentResource), 'document');
      return answer(true);
    }
    if (context === undefined || context.catalog === undefined) {
      return answer(false, `${idOf(kind, object)}: the IAM has composed nothing yet to check it against`);
    }
    const elsewhere = await heldElsewhere(kind, object, context);
    if (elsewhere !== undefined) return answer(false, `${idOf(kind, object)}: ${elsewhere}`);

    const problems =
      kind === 'AuthzRole'
        ? await roleProblems(object, request?.oldObject, context)
        : kind === 'AuthzSeparation'
          ? await separationProblems(object, context)
          : resourceNameProblems(object, context);
    return problems.length === 0 ? answer(true) : answer(false, `${idOf(kind, object)}:\n  ${problems.join('\n  ')}`);
  } catch (error) {
    return answer(false, (error as Error).message);
  }
}
