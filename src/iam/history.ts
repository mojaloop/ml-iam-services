import { serviceOf } from '../authzgen/permission';
import { ServiceCatalog } from '../authzgen/types';
import { PermissionIndex, RoleDocument } from './roles';

/**
 * Every permission the deployment has ever composed, and what became of the
 * ones that are gone: renamed to another, or removed. A service changes its
 * API without telling anyone, so this is what tells a renamed permission from
 * a removed one, and a removed one from a typo.
 */
export interface History {
  known: Record<string, { method: string; path: string }>;
  /** A permission that is gone, mapped to the one that took it over. */
  renamed: Record<string, string>;
  removed: string[];
}

export const EMPTY: History = { known: {}, renamed: {}, removed: [] };

const shape = (path: string): string => path.replace(/\{[^}]+\}/g, '{}');

/**
 * The history after a composition. A permission of a composed service that
 * the catalog no longer has is renamed to the one declaring it replaces it,
 * else to a new one of the same service at the same method and path, else it
 * is removed. Nothing is decided for a service that is not composed at all,
 * since its roles wait for it.
 */
export function advance(history: History, catalog: ServiceCatalog[]): History {
  const current = new Map(catalog.flatMap((c) => c.permissions.map((p) => [p.id, p])));
  const composed = new Set(catalog.map((c) => c.service));
  const renamed: Record<string, string> = {};
  const removed = new Set<string>();

  for (const [id, was] of Object.entries(history.known)) {
    if (current.has(id) || !composed.has(serviceOf(id))) continue;
    const candidates = [...current.values()].filter((p) => serviceOf(p.id) === serviceOf(id));
    const declared = candidates.find((p) => (p.replaces ?? []).includes(id));
    const detected = candidates.find(
      (p) => !(p.id in history.known) && p.method === was.method && shape(p.path) === shape(was.path),
    );
    const next = declared ?? detected;
    if (next !== undefined) renamed[id] = next.id;
    else removed.add(id);
  }
  for (const [id, to] of Object.entries(history.renamed)) {
    if (!current.has(id) && !(id in renamed) && (current.has(to) || !composed.has(serviceOf(id)))) renamed[id] = to;
  }
  for (const id of history.removed) if (!current.has(id) && !(id in renamed) && !composed.has(serviceOf(id))) removed.add(id);

  const resolve = (id: string, seen = new Set<string>()): string => {
    const to = renamed[id];
    if (to === undefined || seen.has(id)) return id;
    seen.add(id);
    return current.has(to) ? to : resolve(to, seen);
  };
  for (const id of Object.keys(renamed)) renamed[id] = resolve(id);

  const known = { ...history.known };
  for (const p of current.values()) known[p.id] = { method: p.method, path: p.path };
  return { known, renamed, removed: [...removed].sort() };
}

/**
 * A role read through the history: a grant naming a renamed permission holds
 * under its new name, one naming a removed permission is dropped, and each is
 * said, so whoever owns the role updates it. A name the history never saw is
 * left for validation to refuse.
 */
export function resolveRole(role: RoleDocument, history: History, index: PermissionIndex): { role: RoleDocument; warnings: string[] } {
  const warnings: string[] = [];
  const grants = role.grants.flatMap((grant) => {
    if (index.has(grant.permission)) return [grant];
    const to = history.renamed[grant.permission];
    if (to !== undefined && index.has(to)) {
      warnings.push(`${grant.permission} is now ${to}; the grant holds under the new name`);
      return [{ ...grant, permission: to }];
    }
    if (history.removed.includes(grant.permission)) {
      warnings.push(`${grant.permission} was removed from ${serviceOf(grant.permission)}; its grant is dropped`);
      return [];
    }
    return [grant];
  });
  return { role: { ...role, grants }, warnings };
}
