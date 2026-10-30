import { RelationshipPatch } from '@ory/client';

import { KetoWriter } from '../../src/iam/keto';
import { Tuple } from '../../src/iam/materialize';

const matches = (t: Tuple, params: Record<string, string>): boolean =>
  Object.entries(params).every(([key, value]) => {
    if (value === undefined) return true;
    if (key === 'subject_set.namespace') return t.subject_set?.namespace === value;
    if (key === 'subject_set.object') return t.subject_set?.object === value;
    if (key === 'subject_set.relation') return t.subject_set?.relation === value;
    return (t as unknown as Record<string, unknown>)[key] === value;
  });

const same = (a: Tuple, b: Tuple): boolean =>
  a.namespace === b.namespace &&
  a.object === b.object &&
  a.relation === b.relation &&
  a.subject_id === b.subject_id &&
  a.subject_set?.namespace === b.subject_set?.namespace &&
  a.subject_set?.object === b.subject_set?.object &&
  a.subject_set?.relation === b.subject_set?.relation;

/**
 * Keto's writes: an insert of a held tuple adds a second row; a patch applies
 * its inserts before its deletes, and a delete removes every row of its tuple;
 * a patch naming an undeclared namespace writes nothing.
 */
export class MemoryKeto extends KetoWriter {
  public tuples: Tuple[] = [];
  public patches = 0;

  constructor(public declared: string[] = ['Role', 'Resource']) {
    super('http://keto-write-test', 'http://keto-read-test');
  }

  override async namespaces(): Promise<string[]> {
    return this.declared;
  }

  override async query(params: Record<string, string>): Promise<Tuple[]> {
    return this.tuples.filter((t) => matches(t, params));
  }

  protected override async send(patch: RelationshipPatch[]): Promise<void> {
    const unknown = patch.find((p) => !this.declared.includes(p.relation_tuple!.namespace));
    if (unknown !== undefined) throw new Error(`Unknown namespace with name "${unknown.relation_tuple!.namespace}"`);
    this.patches += 1;
    for (const p of patch.filter((p) => p.action === 'insert')) this.tuples.push(p.relation_tuple as Tuple);
    for (const p of patch.filter((p) => p.action === 'delete')) {
      this.tuples = this.tuples.filter((t) => !same(t, p.relation_tuple as Tuple));
    }
  }

  override async deleteWhere(params: Record<string, string>): Promise<void> {
    this.tuples = this.tuples.filter((t) => !matches(t, params));
  }
}
