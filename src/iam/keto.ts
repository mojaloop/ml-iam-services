import { Configuration, RelationshipApi, RelationshipPatch } from '@ory/client';

import { MEMBERS, ROLE_NAMESPACE, Tuple } from './materialize';

/** Keto's admin API. Only the IAM holds the write URL. */
export class KetoWriter {
  private readonly reads: RelationshipApi;
  private readonly writes: RelationshipApi;

  constructor(writeUrl: string, readUrl: string = writeUrl) {
    this.reads = new RelationshipApi(new Configuration({ basePath: readUrl }));
    this.writes = new RelationshipApi(new Configuration({ basePath: writeUrl }));
  }

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

  /**
   * Applied whole or not at all: one tuple in a namespace the model lacks
   * refuses the entire patch. A tuple both inserted and deleted in one patch
   * ends up with no row, so a patch holding both is refused before it is sent.
   */
  async patch(inserts: Tuple[], deletes: Tuple[]): Promise<void> {
    if (inserts.length === 0 && deletes.length === 0) return;
    const deleting = new Set(deletes.map(describe));
    const both = inserts.find((t) => deleting.has(describe(t)));
    if (both !== undefined) throw new Error(`one patch inserts and deletes ${describe(both)}`);
    await this.send([
      ...deletes.map((relation_tuple) => ({ action: 'delete' as const, relation_tuple })),
      ...inserts.map((relation_tuple) => ({ action: 'insert' as const, relation_tuple })),
    ]);
  }

  protected async send(relationshipPatch: RelationshipPatch[]): Promise<void> {
    await this.writes.patchRelationships({ relationshipPatch });
  }

  /** Keto writes a second row for a tuple it already holds, so a tuple is inserted only when absent. */
  async put(tuple: Tuple): Promise<void> {
    if ((await this.query(filterFor(tuple))).length === 0) await this.patch([tuple], []);
  }

  async grantsOf(roleObject: string, modelled: Set<string>): Promise<Tuple[]> {
    const held = await this.query({
      'subject_set.namespace': ROLE_NAMESPACE,
      'subject_set.object': roleObject,
      'subject_set.relation': MEMBERS,
    });
    return held.filter((tuple) => modelled.has(tuple.namespace));
  }

  /** Removes every tuple matching a filter, which is how a role instance is retired. */
  async deleteWhere(params: Record<string, string>): Promise<void> {
    await this.writes.deleteRelationships(asRequest(params));
  }
}

export const difference = (wanted: Tuple[], held: Tuple[]): { inserts: Tuple[]; deletes: Tuple[] } => {
  const want = new Map(wanted.map((t) => [describe(t), t]));
  const have = new Map(held.map((t) => [describe(t), t]));
  return {
    inserts: [...want].filter(([key]) => !have.has(key)).map(([, t]) => t),
    deletes: [...have].filter(([key]) => !want.has(key)).map(([, t]) => t),
  };
};

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
