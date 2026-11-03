import { broken, heldInstances, holdingsOf } from './exclusions';
import { difference, KetoWriter } from './keto';
import { InvitationState, KratosAdmin } from './kratos';
import {
  HELD_BY,
  heldByMarker,
  materialize,
  materializeRole,
  MEMBERS,
  membership,
  parseInstance,
  ROLE_NAMESPACE,
  Tuple,
} from './materialize';
import { RESOURCE_NAMESPACE } from './registry';
import { openResourceNames, PermissionIndex, RolesFile } from './roles';

/**
 * Making the graph say what the deployment's roles say.
 *
 * It runs when the service starts, which is also when the roles change: the
 * file arrives as configuration, so an edit rolls the pod and the pod applies
 * it. Every grant a role's members hold ends up exactly what the live roles
 * say, whether the deployment named that holding or a service provisioned it
 * at runtime, and a role no longer live holds nothing. The whole change is one
 * write, so no request ever meets a role half rewritten.
 *
 * It never removes a membership. Which people hold which roles is not the
 * file's business — a deployment ships defaults, an operator grants the rest,
 * and dropping what an operator granted because it is absent from a file would
 * be the file quietly overruling them.
 */

const NOT_GRANTS = new Set(['User', ROLE_NAMESPACE, RESOURCE_NAMESPACE]);

export interface Applied {
  at: string;
  roles: number;
  inserted: number;
  deleted: number;
  /** Role instances a service or an operator created, refreshed from the file. */
  instances: number;
  /** Holdings that break a rule the file now declares. */
  findings: Finding[];
  admin?: { email: string; id: string; created: boolean; invited: boolean };
  /** Whose permissions this apply changed, whose sessions end. */
  affected: Affected;
}

/** The subjects a write changed the permissions of, or everyone when it changed a role every signed-in subject holds. */
export interface Affected {
  everyone: boolean;
  subjects: string[];
}

export interface Finding {
  subject: string;
  rule: string;
  message: string;
}

export interface ReconcileOptions {
  /** Without a password, a created admin is invited by email to set one. */
  admin?: { email: string; role: string; kratosAdminUrl: string; kratosPublicUrl?: string; password?: string };
}

/**
 * The instances that exist because something asked for them: a DFSP the
 * connection manager provisioned, a report an operator was granted. They carry
 * a role's grants as the file said them at the time, so a change to the role
 * has to reach them or they keep answering the old way.
 */
function runtimeInstances(
  held: Tuple[],
  file: RolesFile,
  index: PermissionIndex,
): Array<{ role: string; resources: Record<string, string> }> {
  const seen = new Map<string, { role: string; resources: Record<string, string> }>();
  for (const tuple of held) {
    const instance = parseInstance(tuple.object);
    const role = file.roles[instance.role];
    if (role === undefined || openResourceNames(role, index).length === 0) continue;
    seen.set(tuple.object, instance);
  }
  return [...seen.values()];
}

/** Read before the memberships are, so an assignment landing in between is either seen whole or not touched. */
async function heldGrants(keto: KetoWriter, modelled: string[]): Promise<Tuple[]> {
  const held: Tuple[] = [];
  for (const namespace of modelled.filter((n) => !NOT_GRANTS.has(n))) {
    const tuples = await keto.query({ namespace });
    held.push(
      ...tuples.filter((t) => t.subject_set?.namespace === ROLE_NAMESPACE && t.subject_set.relation === MEMBERS),
    );
  }
  return held;
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
      (await kratos.invitationState(options.admin.email)) === InvitationState.none;
    if (invited) await kratos.invite(options.admin.email);
    admin = { ...found, invited };
    tuples.push(membership(options.admin.role, admin.id));
  }

  const modelled = await keto.namespaces();
  const held = await heldGrants(keto, modelled);
  const heldMemberships = await keto.query({ namespace: ROLE_NAMESPACE, relation: MEMBERS });

  const instances = runtimeInstances(heldMemberships, file, index);
  for (const instance of instances) {
    tuples.push(...materializeRole(instance.role, file.roles[instance.role]!, index, instance.resources));
  }

  const { inserts, deletes } = difference(
    tuples.filter((t) => t.subject_set !== undefined),
    held,
  );
  const markers = difference(
    Object.entries(file.roles)
      .filter(([, role]) => role.heldBy !== undefined)
      .map(([name]) => heldByMarker(name)),
    await keto.query({ namespace: ROLE_NAMESPACE, relation: HELD_BY }),
  );
  const absent = difference(
    tuples.filter((t) => t.subject_id !== undefined),
    heldMemberships,
  ).inserts;
  await keto.patch([...inserts, ...markers.inserts, ...absent], [...deletes, ...markers.deletes]);

  const changed = new Set([...inserts, ...deletes].flatMap((t) => (t.subject_set !== undefined ? [t.subject_set.object] : [])));
  const everyone =
    markers.inserts.length + markers.deletes.length > 0 ||
    Object.entries(file.roles).some(([name, role]) => role.heldBy !== undefined && changed.has(heldByMarker(name).object));
  const subjects = [...heldMemberships.filter((t) => changed.has(t.object)), ...absent].flatMap((t) =>
    t.subject_id !== undefined ? [t.subject_id] : [],
  );

  // Rules and holdings change at different times and only holdings pass
  // through a gate, so a rule added today meets combinations granted before it
  // existed. Reported, never repaired: which half to take away is a decision
  // about someone's job.
  const findings: Finding[] = [];
  for (const [subject, held] of await heldInstances(keto)) {
    for (const rule of file.exclusions ?? []) {
      for (const message of broken(holdingsOf(file, held), [rule], index)) {
        findings.push({ subject, rule: rule.name, message });
      }
    }
  }

  return {
    at: new Date().toISOString(),
    roles: Object.keys(file.roles).length,
    inserted: inserts.length,
    deleted: deletes.length,
    instances: instances.length,
    findings,
    affected: { everyone, subjects: [...new Set(subjects)].sort() },
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
  `Applied ${applied.roles} roles: ${applied.inserted} grants written, ${applied.deleted} removed, ${applied.instances} instances refreshed`,
  ...applied.findings.map((f) => `ALREADY HELD  ${f.subject}: ${f.message}`),
];
