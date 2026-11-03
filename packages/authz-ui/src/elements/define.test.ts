import { expect, it } from 'vitest';

import {
  ElementTag,
  IamAssignmentEditorElement,
  IamRoleEditorElement,
  IamRolesElement,
  IamSubjectsElement,
} from './index';

it('registers every element as soon as it is loaded', async () => {
  for (const tag of Object.values(ElementTag)) expect(customElements.get(tag)).toBeUndefined();
  await import('./define');
  expect(customElements.get(ElementTag.roles)).toBe(IamRolesElement);
  expect(customElements.get(ElementTag.subjects)).toBe(IamSubjectsElement);
  expect(customElements.get(ElementTag.roleEditor)).toBe(IamRoleEditorElement);
  expect(customElements.get(ElementTag.assignmentEditor)).toBe(IamAssignmentEditorElement);
});
