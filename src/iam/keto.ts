import { Configuration, RelationshipApi } from '@ory/client';

import { MEMBERS, ROLE_NAMESPACE, Tuple } from './materialize';

interface QueryResponse {
  relation_tuples?: Tuple[];
  next_page_token?: string;
}

/** Keto's admin API. Only the IAM holds the write URL. */
export class KetoWriter {
  private readonly relationships: RelationshipApi;

  constructor(
    private readonly writeUrl: string,
    private readonly readUrl: string = writeUrl,
  ) {
    this.relationships = new RelationshipApi(new Configuration({ basePath: readUrl }));
  }

  /**
   * The namespaces Keto holds. It reads them from the file it watches, and
   * reports readiness on its database and migrations alone, so this is the
   * only thing that says whether the model has reached it.
   */
  async namespaces(): Promise<string[]> {
    const { data } = await this.relationships.listRelationshipNamespaces();
    return (data.namespaces ?? []).flatMap((entry) => (entry.name === undefined ? [] : [entry.name]));
  }

  /** Every tuple matching the filter, following Keto's pagination to the end. */
  async query(params: Record<string, string>): Promise<Tuple[]> {
    const tuples: Tuple[] = [];
    let pageToken = '';
    do {
      const query = new URLSearchParams(pageToken ? { ...params, page_token: pageToken } : params);
      const response = await fetch(`${this.readUrl}/relation-tuples?${query.toString()}`);
      if (!response.ok) throw new Error(`Keto query answered ${response.status}`);
      const body = (await response.json()) as QueryResponse;
      tuples.push(...(body.relation_tuples ?? []));
      pageToken = body.next_page_token ?? '';
    } while (pageToken);
    return tuples;
  }

  /** Keto stores a second row for a tuple it already holds, so writing is delete-then-put. */
  async put(tuple: Tuple): Promise<void> {
    await this.deleteWhere(filterFor(tuple));
    const response = await fetch(`${this.writeUrl}/admin/relation-tuples`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tuple),
    });
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`Keto rejected ${response.status} for ${describe(tuple)}: ${detail.trim()}`);
    }
  }

  async putAll(tuples: Tuple[]): Promise<void> {
    for (const tuple of tuples) await this.put(tuple);
  }

  /**
   * Drops every grant a role instance holds, so writing its grants afterwards
   * leaves exactly what the role document says. Without this a permission
   * removed from a role would survive the next deploy.
   */
  async clearGrantsOf(roleObject: string): Promise<void> {
    const held = await this.query({
      'subject_set.namespace': ROLE_NAMESPACE,
      'subject_set.object': roleObject,
      'subject_set.relation': MEMBERS,
    });
    for (const tuple of held) await this.deleteWhere(filterFor(tuple));
  }

  /** Removes every tuple matching a filter, which is how a role instance is retired. */
  async deleteWhere(params: Record<string, string>): Promise<void> {
    const query = new URLSearchParams(params);
    const response = await fetch(`${this.writeUrl}/admin/relation-tuples?${query.toString()}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      throw new Error(`Keto rejected ${response.status} deleting ${query.toString()}: ${(await response.text()).trim()}`);
    }
  }
}

/** The query that names exactly one tuple, and no other. */
export const filterFor = (t: Tuple): Record<string, string> => ({
  namespace: t.namespace,
  object: t.object,
  relation: t.relation,
  ...(t.subject_id !== undefined
    ? { subject_id: t.subject_id }
    : {
        'subject_set.namespace': t.subject_set!.namespace,
        'subject_set.object': t.subject_set!.object,
        'subject_set.relation': t.subject_set!.relation,
      }),
});

export const describe = (t: Tuple): string =>
  `${t.namespace}:${t.object}#${t.relation}@${
    t.subject_id ?? `${t.subject_set!.namespace}:${t.subject_set!.object}#${t.subject_set!.relation}`
  }`;
