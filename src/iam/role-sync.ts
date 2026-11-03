import { Localized } from '../authzgen/compose';
import { serviceOf } from '../authzgen/permission';
import { ServiceCatalog } from '../authzgen/types';
import { Logged } from '../logged';
import type { AuthzRole, AuthzSeparation } from '../operator/cluster';
import { Reason, Verdict } from './conditions';
import { roleBreaks, ruleProblems, Within } from './exclusions';
import { History, resolveRole } from './history';
import { KetoWriter } from './keto';
import { Kind, VerdictKind } from './kinds';
import { claimNames, DeploymentObject, idOf, rolesFileOf, writeStatus } from './objects';
import { Applied, applyRoles, ReconcileOptions, report } from './reconcile';
import { HeldBy, indexCatalogs, openResourceNames, RoleDocument, RoleGrant, RolesFile, validateRoles } from './roles';

/** What became of each object of a kind, by name. */
type Verdicts = Record<VerdictKind, Map<string, Verdict>>;
type Warnings = Record<VerdictKind, Map<string, string[]>>;

/**
 * Keeps Keto holding what the deployment's roles and separation rules say,
 * every time one of them or the composition changes, and tells each object
 * what became of it. An object that waits or is refused holds nothing; every
 * other one is applied.
 */

export interface RoleSyncOptions {
  keto: KetoWriter;
  /** The composition the roles are checked against, read at each pass. */
  catalog: () => ServiceCatalog[];
  /** The IAM's own resource names, the only ones a grant names by id. */
  own: () => ReadonlySet<string>;
  /** Waits until Keto declares a namespace, before anything is written into it. */
  ready: (namespace: string) => Promise<void>;
  /** Called with what is live after every apply, and what waits for a service. */
  onApplied: (live: RolesFile, applied: Applied, pending: string[], waiting: Record<string, RoleDocument>) => void;
  /** The first administrator, made a member when the roles are first applied. */
  admin?: ReconcileOptions['admin'];
  /** Every Keto namespace a set of roles writes into. */
  namespacesOf: (file: RolesFile) => string[];
  /** Runs a write to the graph alone, so no assignment interleaves with an apply. */
  exclusive: <T>(write: () => Promise<T>) => Promise<T>;
  /** Called after every pass with what became of each object. */
  onTold: (roles: RoleView[], rules: RuleView[]) => void;
  /** The deployment's role and separation objects as they stand. */
  objects: () => Promise<{ roles: AuthzRole[]; separations: AuthzSeparation[] }>;
  /** Writes what became of one object onto it. */
  setStatus: (kind: VerdictKind, namespace: string, name: string, status: Record<string, unknown>) => Promise<void>;
  /** What became of the permissions services no longer offer. */
  history: () => History;
  /** Whether an object is one the IAM keeps, which it moves to a permission's new name itself. */
  owns: (object: AuthzRole) => boolean;
  /** Writes an owned role's grants back under the names its permissions now have. */
  rewrite: (object: AuthzRole, grants: RoleGrant[]) => Promise<void>;
}

export interface RoleView {
  name: string;
  namespace: string;
  labels: Record<string, string>;
  title?: Localized;
  description?: Localized;
  heldBy?: HeldBy;
  grants: RoleGrant[];
  open: string[];
  ready: Verdict;
}

export interface RuleView {
  name: string;
  namespace: string;
  description?: Localized;
  within: Within;
  resourceName?: string;
  groups: string[][];
  ready: Verdict;
  violations: string[];
}

const servicesOf = (ids: string[]): string[] => [...new Set(ids.map(serviceOf))].sort();

export class RoleSync {
  private running = false;
  private again = false;
  private appliedAs?: string;
  private applied?: Applied;

  constructor(private readonly options: RoleSyncOptions) {}

  schedule(): void {
    this.run().catch((error) => console.error(JSON.stringify({ event: Logged.roleSyncFailed, error: String(error) })));
  }

  /** One pass; calls that overlap it collapse into one more pass afterwards. */
  async run(): Promise<void> {
    if (this.running) {
      this.again = true;
      return;
    }
    this.running = true;
    try {
      await this.pass();
    } finally {
      this.running = false;
      if (this.again) {
        this.again = false;
        await this.run();
      }
    }
  }

  private async pass(): Promise<void> {
    const { roles: roleObjects, separations: ruleObjects } = await this.options.objects();
    const roles = claimNames(Kind.role, roleObjects);
    const rules = claimNames(Kind.separation, ruleObjects);
    const file = rolesFileOf(roles.owners, rules.owners);
    const catalog = this.options.catalog();
    const index = indexCatalogs(catalog);
    const composed = new Set(catalog.map((c) => c.service));
    const absent = (ids: string[]) => servicesOf(ids).filter((s) => !composed.has(s));

    const verdicts: Verdicts = { [Kind.role]: new Map(), [Kind.separation]: new Map() };
    const warnings: Warnings = { [Kind.role]: new Map(), [Kind.separation]: new Map() };
    const live: RolesFile = { roles: {}, exclusions: [] };
    const waitingRoles: Record<string, RoleDocument> = {};
    const history = this.options.history();

    for (const original of file.exclusions ?? []) {
      const said: string[] = [];
      const groups = original.groups.map((group) =>
        group.flatMap((id) => {
          const { role, warnings: found } = resolveRole({ grants: [{ permission: id }] }, history, index);
          said.push(...found);
          return role.grants.map((g) => g.permission);
        }),
      );
      const rule = { ...original, groups };
      if (said.length > 0) warnings[Kind.separation].set(rule.name, said);
      const missing = absent(rule.groups.flat());
      const problems = ruleProblems(rule, index);
      if (missing.length > 0) verdicts[Kind.separation].set(rule.name, { reason: Reason.waiting, message: `waits for ${missing.join(', ')}` });
      else if (problems.length > 0) verdicts[Kind.separation].set(rule.name, { reason: Reason.refused, message: problems.join('; ') });
      else live.exclusions!.push(rule);
    }

    for (const [name, original] of Object.entries(file.roles)) {
      const { role, warnings: said } = resolveRole(original, history, index);
      if (said.length > 0) {
        warnings[Kind.role].set(name, said);
        const object = roles.owners.find((o) => o.metadata?.name === name);
        if (object !== undefined && this.options.owns(object)) {
          await this.options.rewrite(object, role.grants).catch((error) =>
            console.error(JSON.stringify({ event: Logged.roleRewriteFailed, role: name, error: String(error) })),
          );
        }
      }
      const missing = absent(role.grants.map((g) => g.permission));
      const problems = validateRoles({ roles: { [name]: role }, exclusions: live.exclusions }, index, this.options.own());
      if (missing.length > 0) {
        verdicts[Kind.role].set(name, { reason: Reason.waiting, message: `waits for ${missing.join(', ')}` });
        waitingRoles[name] = role;
      } else if (problems.length > 0) verdicts[Kind.role].set(name, { reason: Reason.refused, message: problems.join('; ') });
      else live.roles[name] = role;
    }

    const signature = JSON.stringify([live, waitingRoles, catalog]);
    if (signature !== this.appliedAs) {
      for (const namespace of this.options.namespacesOf(live)) await this.options.ready(namespace);
      const first = this.applied === undefined;
      const applied = await this.options.exclusive(() =>
        applyRoles(this.options.keto, live, index, first && this.options.admin !== undefined ? { admin: this.options.admin } : {}),
      );
      for (const line of report(applied)) console.log(line);
      this.applied = applied;
      this.appliedAs = signature;
      const waiting = (kind: VerdictKind, noun: string): string[] =>
        [...verdicts[kind]].filter(([, v]) => v.reason === Reason.waiting).map(([name, v]) => `${noun} ${name} ${v.message}`);
      const pending = [...waiting(Kind.role, 'role'), ...waiting(Kind.separation, 'separation')];
      this.options.onApplied(live, applied, pending, waitingRoles);
    }

    const told = await this.tellRoles(roleObjects, roles.refused, verdicts, warnings, live, index);
    this.options.onTold(told, await this.tellRules(ruleObjects, rules.refused, verdicts, warnings, live, index));
  }

  private async tellRoles(
    objects: AuthzRole[],
    duplicates: Map<AuthzRole, string>,
    verdicts: Verdicts,
    warnings: Warnings,
    live: RolesFile,
    index: ReturnType<typeof indexCatalogs>,
  ): Promise<RoleView[]> {
    const views: RoleView[] = [];
    for (const object of objects) {
      const name = object.metadata?.name ?? '';
      const role = live.roles[name];
      const said = duplicates.has(object) ? [] : (warnings[Kind.role].get(name) ?? []);
      const verdict: Verdict = duplicates.has(object)
        ? { reason: Reason.refused, message: duplicates.get(object)! }
        : (verdicts[Kind.role].get(name) ??
          (role?.heldBy !== undefined
            ? { reason: Reason.accepted, message: [`${role.grants.length} grants, held by every ${role.heldBy} subject`, ...said].join('; ') }
            : { reason: Reason.accepted, message: [`${role?.grants.length ?? 0} grants`, ...said].join('; ') }));
      const open = role !== undefined && verdict.reason === Reason.accepted ? openResourceNames(role, index) : [];
      await this.status(Kind.role, object, verdict, { open, warnings: said });
      const spec = object.spec ?? {};
      views.push({
        name,
        namespace: object.metadata?.namespace ?? '',
        labels: object.metadata?.labels ?? {},
        ...(spec.title !== undefined ? { title: spec.title } : {}),
        ...(spec.description !== undefined ? { description: spec.description } : {}),
        ...(spec.heldBy !== undefined ? { heldBy: spec.heldBy } : {}),
        grants: spec.grants ?? [],
        open: openResourceNames({ grants: spec.grants ?? [] }, index),
        ready: verdict,
      });
    }
    return views;
  }

  private async tellRules(
    objects: AuthzSeparation[],
    duplicates: Map<AuthzSeparation, string>,
    verdicts: Verdicts,
    warnings: Warnings,
    live: RolesFile,
    index: ReturnType<typeof indexCatalogs>,
  ): Promise<RuleView[]> {
    const views: RuleView[] = [];
    for (const object of objects) {
      const name = object.metadata?.name ?? '';
      const said = duplicates.has(object) ? [] : (warnings[Kind.separation].get(name) ?? []);
      const rule = live.exclusions?.find((r) => r.name === name);
      const violations = [...new Set((this.applied?.findings ?? []).filter((f) => f.rule === name).map((f) => f.subject))].sort();
      const spanning = rule === undefined
        ? []
        : Object.entries(live.roles)
          .filter(([, role]) => roleBreaks(role, [rule], index).length > 0)
          .map(([role]) => role);
      const verdict: Verdict = duplicates.has(object)
        ? { reason: Reason.refused, message: duplicates.get(object)! }
        : (verdicts[Kind.separation].get(name) ?? {
          reason: Reason.accepted,
          message: [
            violations.length === 0 ? 'no subject breaks it' : `${violations.length} subjects already break it`,
            ...(spanning.length > 0 ? [`roles holding both groups on their own: ${spanning.join(', ')}`] : []),
            ...said,
          ].join('; '),
        });
      await this.status(Kind.separation, object, verdict, { violations: rule === undefined ? [] : violations, warnings: said });
      const spec = object.spec ?? {};
      views.push({
        name,
        namespace: object.metadata?.namespace ?? '',
        ...(spec.description !== undefined ? { description: spec.description } : {}),
        within: spec.within ?? Within.subject,
        ...(spec.resourceName !== undefined ? { resourceName: spec.resourceName } : {}),
        groups: spec.groups ?? [],
        ready: verdict,
        violations: rule === undefined ? [] : violations,
      });
    }
    return views;
  }

  private async status(
    kind: VerdictKind,
    object: DeploymentObject,
    verdict: Verdict,
    fields: Record<string, unknown>,
  ): Promise<void> {
    await writeStatus(object, verdict, fields, (namespace, name, status) => this.options.setStatus(kind, namespace, name, status)).catch(
      (error) => console.error(JSON.stringify({ event: Logged.statusFailed, object: idOf(kind, object), error: String(error) })),
    );
  }
}
