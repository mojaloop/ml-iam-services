import { KetoWriter } from '../../src/iam/keto';
import { ROLE_NAMESPACE } from '../../src/iam/materialize';
import { waitForModel } from '../../src/iam/server';

const holding = (keto: KetoWriter, answers: string[][]): string[][] => {
  const remaining = [...answers];
  keto.namespaces = async () => {
    const next = remaining.shift();
    if (next === undefined) throw new Error('asked once more than the test allows');
    return next;
  };
  return remaining;
};

describe('applying roles before Keto has read the model', () => {
  it('holds until the role namespace appears', async () => {
    const keto = new KetoWriter('http://keto-write', 'http://keto-read');
    const remaining = holding(keto, [[], ['Resource'], ['Resource', ROLE_NAMESPACE]]);

    await waitForModel(keto, ROLE_NAMESPACE);

    expect(remaining).toHaveLength(0);
  });

  it('holds while Keto refuses to answer at all', async () => {
    const keto = new KetoWriter('http://keto-write', 'http://keto-read');
    let asked = 0;
    keto.namespaces = async () => {
      asked += 1;
      if (asked < 3) throw new Error('connect ECONNREFUSED');
      return [ROLE_NAMESPACE];
    };

    await waitForModel(keto, ROLE_NAMESPACE);

    expect(asked).toBe(3);
  });

  it('clears a role only of grants in namespaces the model still has', async () => {
    const keto = new KetoWriter('http://keto-write', 'http://keto-read');
    const grant = (namespace: string) => ({
      namespace,
      object: '__self__',
      relation: 'view',
      subject_set: { namespace: ROLE_NAMESPACE, object: 'intapi-client', relation: 'members' },
    });
    keto.query = async () => [grant('intapi'), grant('lookup')];
    keto.namespaces = async () => [ROLE_NAMESPACE, 'lookup'];
    const deleted: string[] = [];
    keto.deleteWhere = async (params) => {
      if (params['namespace'] !== 'lookup') throw new Error(`Keto has no namespace ${params['namespace']}`);
      deleted.push(params['namespace']);
    };

    await keto.clearGrantsOf('intapi-client');

    expect(deleted).toEqual(['lookup']);
  });

  it('returns at once when the model is already there', async () => {
    const keto = new KetoWriter('http://keto-write', 'http://keto-read');
    const remaining = holding(keto, [[ROLE_NAMESPACE]]);

    await waitForModel(keto, ROLE_NAMESPACE);

    expect(remaining).toHaveLength(0);
  });
});
