import { describe, expect, it } from 'vitest';

import { formatScope, parseScope } from '~/header';
import { ALL, idProblem } from '~/reserved';

describe('what can be a resource id', () => {
  it('is any text a reserved word or the scope cannot mistake', () => {
    expect(idProblem('dfsp-a')).toBeUndefined();
  });

  it.each([
    ['nothing', ''],
    ['a reserved word', ALL],
    ['a reserved start', '$own'],
    ['what separates ids', 'a,b'],
    ['what separates types', 'a;b'],
  ])('is never %s', (_label, id) => {
    expect(idProblem(id)).toBeDefined();
  });

  it('travels through the scope a service is handed unchanged', () => {
    const scope = new Map([['orders', { all: false, ids: ['o=1', 'o-2'] }]]);
    expect(parseScope({ 'x-scope': formatScope(scope) })).toEqual(scope);
  });
});
