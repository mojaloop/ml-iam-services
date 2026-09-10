import { Configuration, RelationshipApi } from '@ory/client';

import { MEMBERS, ROLE_NAMESPACE, Tuple } from './materialize';

/** Keto's admin API. Only the IAM holds the write URL. */
export class KetoWriter {
  /** Keto serves reads and writes on separate ports, so each gets its own client. */
  private readonly reads: RelationshipApi;
  private readonly writes: RelationshipApi;

  constructor(writeUrl: string, readUrl: string = writeUrl) {
    this.reads = new RelationshipApi(new Configuration({ basePath: readUrl }));
    this.writes = new RelationshipApi(new Configuration({ basePath: writeUrl }));
  }

  /**
   * The namespaces Keto holds. It reads them from the file it watches, and
   * reports readiness on its database and migrations alone, so this is the
   * only thing that says whether the model has reached it.
   */
  async namespaces(): Promise<string[]> {
    const { data } = await this.reads.listRelationshipNamespaces();
    return (data.namespaces ?? []).flatMap((entry) => (entry.name === undefined ? [] : [entry.name]));
  }

  /** Every tuple matching the filter, following Keto's pagination to the end. */
  async query(params: Record<string, string>): Promise<Tuple[]> {
    const tuples: Tuple[] = [];
    let pageToken: string | undefined;
    do {
      const { data } = await this.reads.getRelationships({ ...asRequest(params), pageToken });
      tuples.push(...((data.relation_tuples ?? []) as Tuple[]));
      pageToken = data.next_page_token === '' ? undefined : data.next_page_token;
    } while (pageToken !== undefined);
    return tuples;
  }

  /** Keto stores a second row for a tuple it already holds, so writing is delete-then-put. */
  async put(tuple: Tuple): Promise<void> {
    await this.deleteWhere(filterFor(tuple));
    await this.writes.createRelationship({ createRelationshipBody: tuple });
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
    await this.writes.deleteRelationships(asRequest(params));
  }
}

/** The filters this reads and writes by, under the names the client gives them. */
const asRequest = (params: Record<string, string>) => ({
  namespace: params['namespace'],
  object: params['object'],
  relation: params['relation'],
  subjectId: params['subject_id'],
  subjectSetNamespace: params['subject_set.namespace'],
  subjectSetObject: params['subject_set.object'],
  subjectSetRelation: params['subject_set.relation'],
});

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
