import { isDeepStrictEqual } from 'node:util';

import { ResourceName, ResourceNames } from '../authzgen/compose';
import { describeObject, refOf } from '../authzgen/problem';
import { readyCondition, Verdict } from './conditions';
import { Exclusion, Within } from './exclusions';
import { HeldBy, RoleDocument, RolesFile } from './roles';

/**
 * The deployment's data as it arrives: one Kubernetes object per role,
 * separation rule and resource name, in any namespace, each named once
 * across the cluster.
 */

export interface DeploymentObject {
  metadata?: {
    name?: string;
    namespace?: string;
    generation?: number;
    uid?: string;
    creationTimestamp?: Date | string;
    labels?: Record<string, string>;
  };
  status?: { conditions?: Parameters<typeof readyCondition>[0]; [field: string]: unknown };
}

export const idOf = (kind: string, object: DeploymentObject): string => `${kind}/${describeObject(refOf(object.metadata))}`;

const createdAt = (object: DeploymentObject): string => {
  const at = object.metadata?.creationTimestamp;
  return at === undefined ? '' : new Date(at).toISOString();
};

/**
 * A name is held by its oldest object; one created later under the same name
 * in another namespace is refused, so a reference by name always means one
 * object.
 */
export function claimNames<T extends DeploymentObject>(
  kind: string,
  objects: T[],
): { owners: T[]; refused: Map<T, string> } {
  const ordered = [...objects].sort((a, b) => {
    const [first, second] = [refOf(a.metadata), refOf(b.metadata)];
    return (
      createdAt(a).localeCompare(createdAt(b)) ||
      first.namespace.localeCompare(second.namespace) ||
      first.name.localeCompare(second.name)
    );
  });
  const owners = new Map<string, T>();
  const refused = new Map<T, string>();
  for (const object of ordered) {
    const name = object.metadata?.name ?? '';
    const owner = owners.get(name);
    if (owner === undefined) owners.set(name, object);
    else refused.set(object, `${name} is already defined by ${idOf(kind, owner)}; a name is unique across the cluster`);
  }
  return { owners: [...owners.values()], refused };
}

export interface RoleSpec {
  heldBy?: HeldBy;
  grants?: RoleDocument['grants'];
}

export interface SeparationSpec {
  within?: Within;
  resourceName?: string;
  groups?: string[][];
}

export const roleOf = (spec: RoleSpec | undefined): RoleDocument => ({
  grants: spec?.grants ?? [],
  ...(spec?.heldBy !== undefined ? { heldBy: spec.heldBy } : {}),
});

export const exclusionOf = (name: string, spec: SeparationSpec | undefined): Exclusion => ({
  name,
  groups: spec?.groups ?? [],
  within: spec?.within ?? Within.subject,
  ...(spec?.resourceName !== undefined ? { resourceName: spec.resourceName } : {}),
});

export const rolesFileOf = (
  roles: Array<DeploymentObject & { spec?: RoleSpec }>,
  separations: Array<DeploymentObject & { spec?: SeparationSpec }>,
): RolesFile => ({
  roles: Object.fromEntries(roles.map((r) => [r.metadata?.name ?? '', roleOf(r.spec)])),
  exclusions: separations.map((s) => exclusionOf(s.metadata?.name ?? '', s.spec)),
});

export const resourceNamesOf = (objects: Array<DeploymentObject & { spec?: Partial<ResourceName> }>): ResourceNames => ({
  resourceNames: Object.fromEntries(
    objects.map((o) => [
      o.metadata?.name ?? '',
      {
        members: o.spec?.members ?? [],
        ...(o.spec?.label !== undefined ? { label: o.spec.label } : {}),
        ...(o.spec?.description !== undefined ? { description: o.spec.description } : {}),
        ...(o.spec?.source !== undefined ? { source: o.spec.source } : {}),
      },
    ]),
  ),
});

export type StatusWriter = (namespace: string, name: string, status: Record<string, unknown>) => Promise<void>;

/**
 * Writes an object's verdict and fields, and writes nothing when they are what
 * it already says, so the IAM's own writes never move an object it watches.
 */
export async function writeStatus(
  object: DeploymentObject,
  verdict: Verdict,
  fields: Record<string, unknown>,
  write: StatusWriter,
): Promise<void> {
  const namespace = object.metadata?.namespace;
  const name = object.metadata?.name;
  if (namespace === undefined || name === undefined) return;
  const generation = object.metadata?.generation;
  const next: Record<string, unknown> = {
    ...(generation !== undefined ? { observedGeneration: generation } : {}),
    conditions: [readyCondition(object.status?.conditions, verdict, generation)],
    ...fields,
  };
  const current = Object.fromEntries(Object.keys(next).map((key) => [key, object.status?.[key]]));
  if (isDeepStrictEqual(current, next)) return;
  await write(namespace, name, next);
}
