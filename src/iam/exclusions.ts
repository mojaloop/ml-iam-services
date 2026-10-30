import { MEMBERS, parseInstance, ROLE_NAMESPACE } from './materialize';
import { ALL, grantResources, PermissionIndex, RoleDocument, RolesFile } from './roles';

/**
 * Separation of duties: groups of permissions a deployment refuses to see in
 * one pair of hands, however many roles it takes to get there.
 *
 * The rule is between permissions, so it holds no matter which role carries
 * them, and it is checked wherever a holding is written: the administrator
 * making the combination is the one who can undo it.
 */

export interface Exclusion {
  /** What the rule is called, so a refusal names the policy it enforces. */
  name: string;
  groups: string[][];
  within?: 'subject' | 'resource';
  /** For `within: resource`, the resource name holdings are compared on. */
  resourceName?: string;
}

/** One role a subject holds, with the resources its assignment named. */
export interface Holding {
  role: RoleDocument;
  resources: Record<string, string>;
}

const resourcesHeld = (
  holding: Holding,
  ids: Set<string>,
  resourceName: string,
  index: PermissionIndex,
): Set<string> => {
  const held = new Set<string>();
  for (const grant of holding.role.grants ?? []) {
    if (!ids.has(grant.permission)) continue;
    const permission = index.get(grant.permission);
    if (permission === undefined) continue;
    const named = grantResources(grant, permission);
    if (!named.has(resourceName)) continue;
    const set = named.get(resourceName) ?? holding.resources[resourceName];
    for (const id of set === undefined ? [] : Array.isArray(set) ? set : [set]) held.add(id);
  }
  return held;
};

const overlap = (a: Set<string>, b: Set<string>): boolean =>
  a.size > 0 && b.size > 0 && (a.has(ALL) || b.has(ALL) || [...a].some((id) => b.has(id)));

/**
 * The rules a set of holdings breaks. `subject` is broken by touching two
 * groups at all; `resource` by holding two groups over one resource, `all`
 * overlapping every other.
 */
export function broken(holdings: Holding[], exclusions: Exclusion[], index: PermissionIndex): string[] {
  const held = new Set(holdings.flatMap((h) => (h.role.grants ?? []).map((g) => g.permission)));
  const problems: string[] = [];
  for (const rule of exclusions) {
    const touched = rule.groups.map((group) => group.filter((id) => held.has(id))).filter((ids) => ids.length > 0);
    if (touched.length < 2) continue;

    if (rule.within === 'resource' && rule.resourceName !== undefined) {
      const over = rule.groups.map((group) => {
        const ids = new Set(group);
        const all = new Set<string>();
        for (const h of holdings) for (const id of resourcesHeld(h, ids, rule.resourceName!, index)) all.add(id);
        return all;
      });
      const pairs = over.flatMap((a, i) => over.slice(i + 1).map((b, j) => [i, i + 1 + j, overlap(a, b)] as const));
      const meet = pairs.find(([, , met]) => met);
      if (meet !== undefined) {
        problems.push(
          `${rule.name}: ${rule.groups[meet[0]]!.join(',')} cannot be held with ${rule.groups[meet[1]]!.join(',')} over one ${rule.resourceName}`,
        );
      }
      continue;
    }

    problems.push(`${rule.name}: ${touched.map((ids) => ids.join(',')).join(' cannot be held with ')}`);
  }
  return problems;
}

/** Roles by name, for a set of role names a subject holds. */
export const rolesNamed = (file: RolesFile, names: string[]): RoleDocument[] =>
  names.map((name) => file.roles[name]).filter((role): role is RoleDocument => role !== undefined);

/** Holdings from role instances, each read back into its role and the resources it was assigned over. */
export const holdingsOf = (file: RolesFile, instances: Array<{ role: string; resources: Record<string, string> }>): Holding[] =>
  instances.flatMap((i) => (file.roles[i.role] === undefined ? [] : [{ role: file.roles[i.role]!, resources: i.resources }]));

/**
 * Who holds which role instances, as the graph has it. An assignment made
 * through the IAM lives here and nowhere else.
 */
export async function heldInstances(keto: {
  query(params: Record<string, string>): Promise<Array<{ object: string; subject_id?: string }>>;
}): Promise<Map<string, Array<{ role: string; resources: Record<string, string> }>>> {
  const held = new Map<string, Array<{ role: string; resources: Record<string, string> }>>();
  for (const tuple of await keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS })) {
    if (tuple.subject_id === undefined) continue;
    held.set(tuple.subject_id, [...(held.get(tuple.subject_id) ?? []), parseInstance(tuple.object)]);
  }
  return held;
}

/**
 * Every way one rule can be wrong before it ever refuses anything: a
 * permission no service advertises would be a rule that silently never fires,
 * and a `resource` rule over a permission its resource name does not scope
 * compares nothing.
 */
export function ruleProblems(rule: Exclusion, index: PermissionIndex, composed?: Set<string>): string[] {
  const problems: string[] = [];
  if (rule.groups.length < 2 || rule.groups.some((group) => group.length === 0)) {
    problems.push(`${rule.name}: needs two groups, each with a permission`);
  }
  for (const id of rule.groups.flat()) {
    if (composed !== undefined && !composed.has(id.split('.')[0]!)) continue;
    const permission = index.get(id);
    if (permission === undefined) {
      problems.push(`${rule.name}: unknown permission ${id}`);
    } else if (
      rule.within === 'resource' &&
      !Object.values(permission.resourceNames).includes(rule.resourceName ?? '')
    ) {
      problems.push(`${rule.name}: ${id} is not scoped by ${rule.resourceName}`);
    }
  }
  if (rule.within === 'resource' && rule.resourceName === undefined) {
    problems.push(`${rule.name}: within resource names the resource name it compares on`);
  }
  return problems;
}

/** Every rule a role breaks with its own grants: nobody could hold it without breaking the rule. */
export const roleBreaks = (role: RoleDocument, exclusions: Exclusion[], index: PermissionIndex): string[] =>
  broken([{ role, resources: {} }], exclusions, index);

export function validateExclusions(file: RolesFile, index: PermissionIndex): string[] {
  const exclusions = file.exclusions ?? [];
  const problems = exclusions.flatMap((rule) => ruleProblems(rule, index));
  for (const [name, role] of Object.entries(file.roles ?? {})) {
    for (const problem of roleBreaks(role, exclusions, index)) problems.push(`role ${name} breaks ${problem}`);
  }
  const bySubject = new Map<string, Array<{ role: string; resources: Record<string, string> }>>();
  for (const a of file.assignments ?? []) {
    bySubject.set(a.subject, [...(bySubject.get(a.subject) ?? []), { role: a.role, resources: a.resources ?? {} }]);
  }
  for (const [subject, instances] of bySubject) {
    for (const problem of broken(holdingsOf(file, instances), exclusions, index)) {
      problems.push(`${subject} breaks ${problem}`);
    }
  }
  return [...new Set(problems)];
}
