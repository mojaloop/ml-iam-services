// @vitest-environment node
import { expect, it } from 'vitest';

it('names the elements, their events, attributes, parts and theme where no DOM exists to define them in', async () => {
  expect(typeof HTMLElement).toBe('undefined');
  const names = await import('./names');
  expect(Object.values(names.ElementTag)).toContain('iam-role-editor');
  expect(Object.values(names.IamEvent)).toContain('before-save');
  expect(Object.values(names.Attribute)).toContain('api-base');
  expect(Object.values(names.Part)).toContain('toolbar');
  expect(Object.values(names.CssVar)).toContain('--iam-accent');
  expect(Object.values(names.AssignmentChangeKind)).toContain('unassigned');
});
