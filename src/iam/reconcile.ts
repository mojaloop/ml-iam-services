import { Migrations } from '../authzgen/compose';
import { broken, heldRoles, permissionsOf, rolesNamed } from './exclusions';
import { KetoWriter } from './keto';
import { KratosAdmin } from './kratos';
import { materialize, materializeRole, MEMBERS, membership, ROLE_NAMESPACE, Tuple } from './materialize';
import { migrate } from './migrate';
import { parseInstance } from './provisioner';
import { openResourceNames, PermissionIndex, RolesFile } from './roles';

/**
 * Making the graph say what the deployment's roles say.
 *
 * It runs when the service starts, which is also when the roles change: the
 * file arrives as configuration, so an edit rolls the pod and the pod applies
 * it. A role ends up holding exactly its document, whether the deployment named
 * that holding or a service provisioned it at runtime.
 *
 * It never removes a membership. Which people hold which roles is not the
 * file's business — a deployment ships defaults, an operator grants the rest,
 * and dropping what an operator granted because it is absent from a file would
 * be the file quietly overruling them.
 */

export interface Applied {
  at: string;
  roles: number;
  tuples: number;
  /** Role instances a service or an operator created, refreshed from the file. */
  instances: number;
  moved: number;
  retired: number;
  /** Holdings that break a rule the file now declares. */
  findings: string[];
  admin?: { email: string; id: string; created: boolean; invited: boolean };
}

export interface ReconcileOptions {
  migrations?: Migrations;
  /** Without a password, a created admin is invited by email to set one. */
  admin?: { email: string; role: string; kratosAdminUrl: string; kratosPublicUrl?: string; password?: string };
}

/**
 * The instances that exist because something asked for them: a DFSP the
 * connection manager provisioned, a report an operator was granted. They carry
 * a role's grants as the file said them at the time, so a change to the role
 * has to reach them or they keep answering the old way.
 */
async function runtimeInstances(
  keto: KetoWriter,
  file: RolesFile,
  index: PermissionIndex,
): Promise<Array<{ role: string; resources: Record<string, string> }>> {
  const seen = new Map<string, { role: string; resources: Record<string, string> }>();
  for (const tuple of await keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS })) {
    const instance = parseInstance(tuple.object);
    const role = file.roles[instance.role];
    if (role === undefined || openResourceNames(role, index).length === 0) continue;
    seen.set(tuple.object, instance);
  }
  return [...seen.values()];
}

export async function applyRoles(
  keto: KetoWriter,
  file: RolesFile,
  index: PermissionIndex,
  options: ReconcileOptions = {},
): Promise<Applied> {
  const tuples: Tuple[] = materialize(file, index);

  let admin: { id: string; created: boolean; invited: boolean } | undefined;
  if (options.admin !== undefined) {
    const kratos = new KratosAdmin(options.admin.kratosAdminUrl, options.admin.kratosPublicUrl);
    const found = await kratos.findOrCreate(options.admin.email, options.admin.password);
    const invited =
      options.admin.password === undefined &&
      options.admin.kratosPublicUrl !== undefined &&
      (await kratos.invitationState(options.admin.email)) === 'none';
    if (invited) await kratos.invite(options.admin.email);
    admin = { ...found, invited };
    tuples.push(membership(options.admin.role, admin.id));
  }

  // Before the roles are written, so a grant made in the console under a
  // permission's old name survives this rollout under the new one.
  const { moved, retired } =
    options.migrations === undefined ? { moved: 0, retired: 0 } : await migrate(keto, options.migrations);

  const instances = await runtimeInstances(keto, file, index);
  for (const instance of instances) {
    tuples.push(...materializeRole(instance.role, file.roles[instance.role]!, index, instance.resources));
  }

  for (const role of new Set(tuples.filter((t) => t.subject_set).map((t) => t.subject_set!.object))) {
    await keto.clearGrantsOf(role);
  }
  await keto.putAll(tuples);

  // Rules and holdings change at different times and only holdings pass
  // through a gate, so a rule added today meets combinations granted before it
  // existed. Reported, never repaired: which half to take away is a decision
  // about someone's job.
  const findings: string[] = [];
  for (const [subject, roles] of await heldRoles(keto)) {
    for (const problem of broken(permissionsOf(rolesNamed(file, roles)), file.exclusions ?? [])) {
      findings.push(`${subject}: ${problem}`);
    }
  }

  return {
    at: new Date().toISOString(),
    roles: Object.keys(file.roles).length,
    tuples: tuples.length,
    instances: instances.length,
    moved,
    retired,
    findings,
    ...(options.admin !== undefined && admin !== undefined
      ? { admin: { email: options.admin.email, ...admin } }
      : {}),
  };
}

/** What was written, for a log a human reads once per rollout. */
export const report = (applied: Applied): string[] => [
  ...(applied.admin
    ? [
      `${applied.admin.created ? 'Created' : 'Found'} ${applied.admin.email} (${applied.admin.id})` +
          (applied.admin.invited ? ', invited by email' : ''),
    ]
    : []),
  ...(applied.moved + applied.retired > 0 ? [`Moved ${applied.moved} grants, retired ${applied.retired}`] : []),
  `Applied ${applied.roles} roles as ${applied.tuples} tuples, ${applied.instances} instances refreshed`,
  ...applied.findings.map((f) => `ALREADY HELD  ${f}`),
];
