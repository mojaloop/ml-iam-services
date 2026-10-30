import { ServiceCatalog } from '../authzgen/types';
import { AuthzRole, AuthzSeparation, listRoles, listSeparations, setStatus } from '../operator/cluster';
import { Verdict } from './conditions';
import { roleBreaks, ruleProblems } from './exclusions';
import { KetoWriter } from './keto';
import { claimNames, DeploymentObject, HELD_BY_UNAPPLIED, idOf, rolesFileOf, writeStatus } from './objects';
import { Applied, applyRoles, ReconcileOptions, report } from './reconcile';
import { indexCatalogs, openResourceNames, RolesFile, validateRoles } from './roles';

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
  /** Waits until Keto declares a namespace, before anything is written into it. */
  ready: (namespace: string) => Promise<void>;
  /** Called with what is live after every apply, and what waits for a service. */
  onApplied: (live: RolesFile, applied: Applied, pending: string[]) => void;
  /** The first administrator, made a member when the roles are first applied. */
  admin?: ReconcileOptions['admin'];
  /** Every Keto namespace a set of roles writes into. */
  namespacesOf: (file: RolesFile) => string[];
}

const servicesOf = (ids: string[]): string[] => [...new Set(ids.map((id) => id.split('.')[0]!))].sort();

export class RoleSync {
  private running = false;
  private again = false;
  private appliedAs?: string;
  private applied?: Applied;

  constructor(private readonly options: RoleSyncOptions) {}

  schedule(): void {
    this.run().catch((error) => console.error(JSON.stringify({ event: 'role-sync-failed', error: String(error) })));
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
    const [roleObjects, ruleObjects] = await Promise.all([listRoles(), listSeparations()]);
    const roles = claimNames('AuthzRole', roleObjects);
    const rules = claimNames('AuthzSeparation', ruleObjects);
    const file = rolesFileOf(roles.owners, rules.owners);
    const catalog = this.options.catalog();
    const index = indexCatalogs(catalog);
    const composed = new Set(catalog.map((c) => c.service));
    const absent = (ids: string[]) => servicesOf(ids).filter((s) => !composed.has(s));

    const verdicts = new Map<string, Verdict>();
    const live: RolesFile = { roles: {}, exclusions: [] };

    for (const rule of file.exclusions ?? []) {
      const missing = absent(rule.groups.flat());
      const problems = ruleProblems(rule, index);
      if (missing.length > 0) verdicts.set(`rule/${rule.name}`, { reason: 'Waiting', message: `waits for ${missing.join(', ')}` });
      else if (problems.length > 0) verdicts.set(`rule/${rule.name}`, { reason: 'Refused', message: problems.join('; ') });
      else live.exclusions!.push(rule);
    }

    for (const [name, role] of Object.entries(file.roles)) {
      const missing = absent(role.grants.map((g) => g.permission));
      const problems = [
        ...(role.heldBy !== undefined ? [`${name}: ${HELD_BY_UNAPPLIED}`] : []),
        ...validateRoles({ roles: { [name]: role }, exclusions: live.exclusions }, index),
      ];
      if (missing.length > 0) verdicts.set(`role/${name}`, { reason: 'Waiting', message: `waits for ${missing.join(', ')}` });
      else if (problems.length > 0) verdicts.set(`role/${name}`, { reason: 'Refused', message: problems.join('; ') });
      else live.roles[name] = role;
    }

    const signature = JSON.stringify([live, catalog]);
    if (signature !== this.appliedAs) {
      for (const namespace of this.options.namespacesOf(live)) await this.options.ready(namespace);
      const first = this.applied === undefined;
      const applied = await applyRoles(
        this.options.keto,
        live,
        index,
        first && this.options.admin !== undefined ? { admin: this.options.admin } : {},
      );
      for (const line of report(applied)) console.log(line);
      this.applied = applied;
      this.appliedAs = signature;
      const pending = [...verdicts]
        .filter(([, v]) => v.reason === 'Waiting')
        .map(([key, v]) => `${key.startsWith('role/') ? 'role' : 'separation'} ${key.split('/')[1]} ${v.message}`);
      this.options.onApplied(live, applied, pending);
    }

    await this.tellRoles(roleObjects, roles.refused, verdicts, live, index);
    await this.tellRules(ruleObjects, rules.refused, verdicts, live, index);
  }

  private async tellRoles(
    objects: AuthzRole[],
    duplicates: Map<AuthzRole, string>,
    verdicts: Map<string, Verdict>,
    live: RolesFile,
    index: ReturnType<typeof indexCatalogs>,
  ): Promise<void> {
    for (const object of objects) {
      const name = object.metadata?.name ?? '';
      const role = live.roles[name];
      const verdict: Verdict = duplicates.has(object)
        ? { reason: 'Refused', message: duplicates.get(object)! }
        : (verdicts.get(`role/${name}`) ?? { reason: 'Accepted', message: `${role?.grants.length ?? 0} grants` });
      const open = role !== undefined && verdict.reason === 'Accepted' ? openResourceNames(role, index) : [];
      await this.status(AuthzRole, object, verdict, { open });
    }
  }

  private async tellRules(
    objects: AuthzSeparation[],
    duplicates: Map<AuthzSeparation, string>,
    verdicts: Map<string, Verdict>,
    live: RolesFile,
    index: ReturnType<typeof indexCatalogs>,
  ): Promise<void> {
    for (const object of objects) {
      const name = object.metadata?.name ?? '';
      const rule = live.exclusions?.find((r) => r.name === name);
      const violations = [...new Set((this.applied?.findings ?? []).filter((f) => f.rule === name).map((f) => f.subject))].sort();
      const spanning = rule === undefined
        ? []
        : Object.entries(live.roles)
          .filter(([, role]) => roleBreaks(role, [rule], index).length > 0)
          .map(([role]) => role);
      const verdict: Verdict = duplicates.has(object)
        ? { reason: 'Refused', message: duplicates.get(object)! }
        : (verdicts.get(`rule/${name}`) ?? {
          reason: 'Accepted',
          message: [
            violations.length === 0 ? 'no subject breaks it' : `${violations.length} subjects already break it`,
            ...(spanning.length > 0 ? [`roles holding both groups on their own: ${spanning.join(', ')}`] : []),
          ].join('; '),
        });
      await this.status(AuthzSeparation, object, verdict, { violations: rule === undefined ? [] : violations });
    }
  }

  private async status(
    model: typeof AuthzRole | typeof AuthzSeparation,
    object: DeploymentObject,
    verdict: Verdict,
    fields: Record<string, unknown>,
  ): Promise<void> {
    await writeStatus(object, verdict, fields, (namespace, name, status) => setStatus(model, namespace, name, status)).catch(
      (error) =>
        console.error(JSON.stringify({ event: 'status-failed', object: idOf(model.name, object), error: String(error) })),
    );
  }
}
