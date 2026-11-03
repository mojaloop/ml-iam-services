import { RelationshipPatch } from '@ory/client';

import { CheckSubject, KetoReader, KetoWriter } from '../../src/iam/keto';
import { SubjectSet, Tuple } from '../../src/iam/materialize';

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
export class MemoryKeto extends KetoWriter implements KetoReader {
  public tuples: Tuple[] = [];
  public patches = 0;

  constructor(public declared: string[] = ['Role', 'Resource']) {
    super('http://keto.invalid', 'http://keto.invalid');
  }

  override async namespaces(): Promise<string[]> {
    return this.declared;
  }

  /** Each read gives way to other work, as a round trip to Keto does, so concurrent writers can interleave. */
  public yielding = false;

  override async query(params: Record<string, string>): Promise<Tuple[]> {
    if (this.yielding) await new Promise((resolve) => setImmediate(resolve));
    return this.tuples.filter((t) => matches(t, params));
  }

  /** Keto's check: a tuple naming the subject, or a subject set the subject is reached through. */
  override async check(namespace: string, object: string, relation: string, subject: CheckSubject): Promise<boolean> {
    const visited = new Set<string>();
    const isSubject = (set: SubjectSet): boolean =>
      typeof subject !== 'string' &&
      set.namespace === subject.namespace &&
      set.object === subject.object &&
      set.relation === subject.relation;
    const reaches = (ns: string, obj: string, rel: string): boolean => {
      const key = `${ns}:${obj}#${rel}`;
      if (visited.has(key)) return false;
      visited.add(key);
      return this.tuples.some(
        (t) =>
          t.namespace === ns &&
          t.object === obj &&
          t.relation === rel &&
          ((typeof subject === 'string' && t.subject_id === subject) ||
            (t.subject_set !== undefined &&
              (isSubject(t.subject_set) || reaches(t.subject_set.namespace, t.subject_set.object, t.subject_set.relation)))),
      );
    };
    return reaches(namespace, object, relation);
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
