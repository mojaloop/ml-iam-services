import { act, fireEvent, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, onTestFinished, vi } from 'vitest';

import componentStyles from '../default.css?inline';
import { BASE, fakeIam } from '../test/fake-iam';
import { alice, holdings, reader, roleStore, world } from '../test/world';
import elementStyles from './element.css?inline';
import {
  AssignmentChangeKind,
  Attribute,
  CssVar,
  defineIamElements,
  ElementTag,
  IamAssignmentEditorElement,
  IamEvent,
  type IamEventMap,
  IamRoleEditorElement,
  IamRolesElement,
  IamSubjectsElement,
  Navigation,
  Part,
} from './index';

type Iam = ReturnType<typeof fakeIam>;

const pageFetch = vi.fn((_: Request) => Promise.reject(new Error('the page fetch was used')));

beforeAll(() => {
  defineIamElements();
  Reflect.set(globalThis, 'IS_REACT_ACT_ENVIRONMENT', false);
});

afterAll(() => {
  Reflect.deleteProperty(globalThis, 'IS_REACT_ACT_ENVIRONMENT');
});

beforeEach(() => {
  vi.stubGlobal('fetch', pageFetch);
});

afterEach(() => {
  document.body.replaceChildren();
  vi.unstubAllGlobals();
  pageFetch.mockClear();
});

/** An element on the page, reaching the fake IAM through the host's fetch and stream. */
function mount<K extends ElementTag>(tag: K, iam: Iam, setup?: (element: HTMLElementTagNameMap[K]) => void) {
  const element = document.createElement(tag);
  element.apiBase = BASE;
  element.fetch = iam.fetch;
  element.eventSource = iam.EventSource;
  setup?.(element);
  document.body.append(element);
  return element;
}

/** What the element renders, inside its shadow root. */
const inside = (element: Element) => within(element.shadowRoot?.querySelector('div') as HTMLElement);

/** Every event of one type that reaches the document, which only a bubbling event does. */
function heard<K extends keyof IamEventMap>(type: K): Array<IamEventMap[K]> {
  const events: Array<IamEventMap[K]> = [];
  const listener = (event: Event) => events.push(event as IamEventMap[K]);
  document.addEventListener(type, listener);
  onTestFinished(() => document.removeEventListener(type, listener));
  return events;
}

const roleItem = async (element: Element, title: string) =>
  (await inside(element).findByText(title)).closest('li') as HTMLElement;

describe('registration', () => {
  it('defines each element under its tag, and defining again changes nothing', () => {
    expect(() => defineIamElements()).not.toThrow();
    expect(customElements.get(ElementTag.roles)).toBe(IamRolesElement);
    expect(customElements.get(ElementTag.subjects)).toBe(IamSubjectsElement);
    expect(customElements.get(ElementTag.roleEditor)).toBe(IamRoleEditorElement);
    expect(customElements.get(ElementTag.assignmentEditor)).toBe(IamAssignmentEditorElement);
  });

  it('leaves a tag that another definition already holds', () => {
    const define = vi.fn();
    defineIamElements({ get: () => HTMLElement, define } as unknown as CustomElementRegistry);
    expect(define).not.toHaveBeenCalled();
  });
});

describe('inputs', () => {
  it("asks the IAM through the fetch the host gives, never the page's", async () => {
    const iam = fakeIam(world);
    const element = mount(ElementTag.roles, iam);
    expect(await inside(element).findByText('Reader')).toBeInTheDocument();
    expect(iam.of('GET', '/roles')).toHaveLength(1);
    expect(pageFetch).not.toHaveBeenCalled();
  });

  it('shows and asks nothing until its api-base attribute says where the IAM is', async () => {
    const iam = fakeIam(world);
    const element = document.createElement(ElementTag.roles);
    element.fetch = iam.fetch;
    element.eventSource = iam.EventSource;
    await act(async () => document.body.append(element));
    expect(element.shadowRoot?.querySelector('div')).toBeEmptyDOMElement();
    expect(iam.requests).toHaveLength(0);
    element.setAttribute(Attribute.apiBase, BASE);
    expect(await inside(element).findByText('Reader')).toBeInTheDocument();
  });

  it('starts afresh when the host changes how it reaches the IAM', async () => {
    const element = mount(ElementTag.roles, fakeIam(world));
    expect(await inside(element).findByText('Reader')).toBeInTheDocument();
    const other = fakeIam({ ...world, 'GET /roles': { body: [{ ...reader, name: 'clerk', title: 'Clerk' }] } });
    element.fetch = other.fetch;
    expect(await inside(element).findByText('Clerk')).toBeInTheDocument();
    expect(inside(element).queryByText('Reader')).toBeNull();
  });

  it('takes the properties a host set before the element was defined', async () => {
    const tag = 'iam-roles-set-early';
    const iam = fakeIam(world);
    const early = document.createElement(tag);
    Object.assign(early, { apiBase: BASE, fetch: iam.fetch, eventSource: iam.EventSource });
    document.body.append(early);
    customElements.define(tag, class extends IamRolesElement {});
    expect(await inside(early).findByText('Reader')).toBeInTheDocument();
    expect(pageFetch).not.toHaveBeenCalled();
  });

  it('shows text in the language its attribute names, and in the words the host gives', async () => {
    const element = mount(ElementTag.roles, fakeIam(world), (roles) => {
      roles.setAttribute(Attribute.language, 'uk');
      roles.messages = { newRole: 'Compose a role' };
    });
    expect(await inside(element).findByText('Читач')).toBeInTheDocument();
    expect(inside(element).getByRole('button', { name: 'Compose a role' })).toBeInTheDocument();
  });

  it('offers what its options allow, set as properties or as attributes', async () => {
    const element = mount(ElementTag.roles, fakeIam(world), (roles) => {
      roles.readOnly = true;
    });
    const view = inside(element);
    expect(within(await roleItem(element, 'Reader')).getByRole('button', { name: 'View' })).toBeInTheDocument();

    element.setAttribute(Attribute.readOnly, 'false');
    expect(await within(await roleItem(element, 'Reader')).findByRole('button', { name: 'Edit' })).toBeInTheDocument();
    expect(view.getByRole('button', { name: 'New role' })).toBeInTheDocument();

    element.setAttribute(Attribute.allowCreate, 'false');
    await waitFor(() => expect(view.queryByRole('button', { name: 'New role' })).toBeNull());

    element.allowOpen = false;
    await waitFor(() => expect(view.queryByRole('button', { name: 'Edit' })).toBeNull());
  });
});

describe('navigation', () => {
  it('tells the host which role to open, or that a new one is asked for, and stays on the list', async () => {
    const element = mount(ElementTag.roles, fakeIam(world));
    const opened = heard(IamEvent.roleOpen);
    await userEvent.click(within(await roleItem(element, 'Reader')).getByRole('button', { name: 'Edit' }));
    await userEvent.click(inside(element).getByRole('button', { name: 'New role' }));
    expect(opened.map((event) => event.detail)).toEqual([{ roleName: 'reader' }, {}]);
    expect(inside(element).queryByRole('textbox')).toBeNull();
  });

  it('opens a role, and a new one, inside the element when navigation is internal', async () => {
    const element = mount(ElementTag.roles, roleStore(), (roles) => {
      roles.navigation = Navigation.internal;
    });
    const opened = heard(IamEvent.roleOpen);
    const view = inside(element);
    await userEvent.click(within(await roleItem(element, 'Reader')).getByRole('button', { name: 'Edit' }));
    expect(await view.findByLabelText('Title')).toHaveValue('Reader');
    await userEvent.click(view.getByRole('button', { name: 'Back' }));
    await userEvent.click(await view.findByRole('button', { name: 'New role' }));
    expect(await view.findByRole('button', { name: 'Create role' })).toBeInTheDocument();
    expect(opened).toHaveLength(0);
  });

  it('composes a new role for a caller who may create roles but not change the ones that exist', async () => {
    const element = mount(ElementTag.roles, roleStore(), (roles) => {
      roles.navigation = Navigation.internal;
      roles.readOnly = true;
    });
    const view = inside(element);
    expect(within(await roleItem(element, 'Reader')).getByRole('button', { name: 'View' })).toBeInTheDocument();
    await userEvent.click(view.getByRole('button', { name: 'New role' }));
    expect(await view.findByLabelText('Name')).toBeEnabled();
    expect(view.getByRole('button', { name: 'Create role' })).toBeInTheDocument();
  });

  it('tells the host which subject to open, and stays on the list', async () => {
    const element = mount(ElementTag.subjects, fakeIam(world));
    const opened = heard(IamEvent.subjectOpen);
    await userEvent.click(await inside(element).findByRole('button', { name: 'Alice' }));
    expect(opened.map((event) => event.detail)).toEqual([{ subject: alice }]);
    expect(inside(element).getByRole('table')).toBeInTheDocument();
  });

  it('opens a subject into what it holds inside the element when navigation is internal', async () => {
    const iam = holdings([{ role: 'reader', resources: { participant: 'p1' }, through: 'assigned' }]);
    const element = mount(ElementTag.subjects, iam, (subjects) => {
      subjects.setAttribute(Attribute.navigation, Navigation.internal);
    });
    const opened = heard(IamEvent.subjectOpen);
    const view = inside(element);
    await userEvent.click(await view.findByRole('button', { name: 'Alice' }));
    expect(await view.findByRole('heading', { name: 'Holds' })).toBeInTheDocument();
    expect(view.getByRole('heading', { name: 'Alice' })).toBeInTheDocument();
    await userEvent.click(view.getByRole('button', { name: 'Back' }));
    expect(await view.findByRole('table')).toBeInTheDocument();
    expect(opened).toHaveLength(0);
  });
});

describe('changes', () => {
  const composeEntryReader = async (element: Element) => {
    const view = inside(element);
    fireEvent.change(await view.findByLabelText('Name'), { target: { value: 'entry-reader' } });
    await userEvent.click(view.getByRole('combobox', { name: 'Add a permission' }));
    await userEvent.click(view.getByRole('option', { name: /^Lists entries/ }));
    await userEvent.click(view.getByRole('button', { name: 'Create role' }));
  };

  it('keeps the role unsent when a before-save listener cancels it', async () => {
    const iam = roleStore();
    const element = mount(ElementTag.roleEditor, iam);
    const asked = heard(IamEvent.beforeSave);
    const saved = heard(IamEvent.roleSaved);
    document.addEventListener(IamEvent.beforeSave, (event) => event.preventDefault(), { once: true });

    await composeEntryReader(element);
    expect(asked.map((event) => event.detail)).toEqual([
      { name: 'entry-reader', spec: { grants: [{ permission: 'ledger.listEntries' }] }, create: true },
    ]);
    expect(asked[0]?.defaultPrevented).toBe(true);
    expect(iam.of('POST', '/roles')).toHaveLength(0);
    expect(saved).toHaveLength(0);

    await userEvent.click(inside(element).getByRole('button', { name: 'Create role' }));
    await waitFor(() => expect(saved).toHaveLength(1));
    expect(iam.of('POST', '/roles')).toHaveLength(1);
  });

  it('hands a before-save listener what will be sent to read, never to change', async () => {
    const iam = roleStore();
    const element = mount(ElementTag.roleEditor, iam);
    const saved = heard(IamEvent.roleSaved);
    const attempts: unknown[] = [];
    document.addEventListener(
      IamEvent.beforeSave,
      (event) => {
        const { detail } = event as CustomEvent<{ name: string; spec: { grants: Array<{ permission: string }> } }>;
        const changes = [
          () => {
            detail.name = 'entry-writer';
          },
          () => {
            detail.spec.grants.push({ permission: 'ledger.createEntry' });
          },
          () => {
            detail.spec.grants[0]!.permission = 'ledger.createEntry';
          },
        ];
        for (const change of changes) {
          try {
            change();
            attempts.push(detail);
          } catch (error) {
            attempts.push(error);
          }
        }
      },
      { once: true },
    );

    await composeEntryReader(element);
    await waitFor(() => expect(saved).toHaveLength(1));
    expect(attempts).toEqual([expect.any(TypeError), expect.any(TypeError), expect.any(TypeError)]);
    expect(iam.of('POST', '/roles')[0]?.body).toEqual({
      name: 'entry-reader',
      grants: [{ permission: 'ledger.listEntries' }],
    });
  });

  it('tells the host a role was composed, then goes on changing it', async () => {
    const element = mount(ElementTag.roleEditor, roleStore());
    const saved = heard(IamEvent.roleSaved);
    await composeEntryReader(element);
    await waitFor(() => expect(saved).toHaveLength(1));
    expect(saved[0]?.detail).toEqual({
      role: { name: 'entry-reader', grants: [{ permission: 'ledger.listEntries' }], open: [], owner: 'iam' },
      created: true,
    });
    expect(await inside(element).findByRole('button', { name: 'Save' })).toBeInTheDocument();
  });

  it('tells the host a role was changed, and that it was deleted', async () => {
    const iam = roleStore();
    const element = mount(ElementTag.roleEditor, iam, (editor) => {
      editor.roleName = 'reader';
      editor.allowDelete = true;
    });
    const saved = heard(IamEvent.roleSaved);
    const deleted = heard(IamEvent.roleDeleted);
    const view = inside(element);
    fireEvent.change(await view.findByLabelText('Title'), { target: { value: 'Entry reader' } });
    await userEvent.click(view.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(saved).toHaveLength(1));
    expect(saved[0]?.detail).toMatchObject({
      role: { name: 'reader', title: { en: 'Entry reader', uk: 'Читач' } },
      created: false,
    });

    await userEvent.click(view.getByRole('button', { name: 'Delete role' }));
    await userEvent.click(view.getByRole('button', { name: 'Delete, and take it from everyone who holds it' }));
    await waitFor(() => expect(deleted.map((event) => event.detail)).toEqual([{ roleName: 'reader' }]));
    expect(iam.of('DELETE', '/roles/reader')).toHaveLength(1);
  });

  it('tells the host each assignment and each removal', async () => {
    const element = mount(ElementTag.assignmentEditor, holdings([]), (editor) => {
      editor.subject = 'alice';
    });
    const changed = heard(IamEvent.assignmentChanged);
    const view = inside(element);
    await userEvent.selectOptions(await view.findByLabelText('Role'), 'Reader');
    await userEvent.selectOptions(await view.findByLabelText('Participant'), 'p2');
    await userEvent.click(view.getByRole('button', { name: 'Assign' }));
    await userEvent.click(await view.findByRole('button', { name: 'Remove' }));
    const assignment = { role: 'reader', resources: { participant: 'p2' } };
    await waitFor(() =>
      expect(changed.map((event) => event.detail)).toEqual([
        { subject: 'alice', assignment, change: AssignmentChangeKind.assigned },
        { subject: 'alice', assignment, change: AssignmentChangeKind.unassigned },
      ]),
    );
  });
});

describe('styles', () => {
  it('keeps its stylesheet inside its shadow root and adds nothing to the page', async () => {
    const head = document.head.innerHTML;
    const element = mount(ElementTag.roles, fakeIam(world));
    await inside(element).findByText('Reader');
    const sheet = element.shadowRoot?.querySelector('style')?.textContent ?? '';
    expect(sheet).toContain('.authz-role-list');
    expect(sheet).toContain(':host');
    expect(sheet).toContain(componentStyles);
    expect(sheet).toContain(elementStyles);
    expect(document.head.innerHTML).toBe(head);
    expect(document.querySelectorAll('style, link')).toHaveLength(0);
  });

  it('names its parts for a host to restyle', async () => {
    const named = (element: Element, part: Part) =>
      element.shadowRoot?.querySelectorAll(`[part~="${part}"]`).length ?? 0;
    const roles = mount(ElementTag.roles, fakeIam(world));
    await inside(roles).findByText('Reader');
    const subjects = mount(ElementTag.subjects, fakeIam(world));
    await inside(subjects).findByText('Alice');
    const editor = mount(ElementTag.roleEditor, fakeIam(world));
    await inside(editor).findByLabelText('Name');

    expect(named(roles, Part.toolbar)).toBe(1);
    expect(named(roles, Part.row)).toBe(3);
    expect(named(roles, Part.actions)).toBe(3);
    expect(named(roles, Part.verdict)).toBe(3);
    expect(named(subjects, Part.table)).toBe(1);
    expect(named(subjects, Part.row)).toBe(2);
    expect(named(editor, Part.form)).toBe(1);
    expect(named(editor, Part.actions)).toBe(1);
    expect(named(editor, Part.primary)).toBe(1);
  });

  it('themes through exactly the --iam-* variables it names', () => {
    const used = new Set(`${componentStyles}${elementStyles}`.match(/--iam-[a-z-]+/g));
    expect([...used].sort()).toEqual(Object.values(CssVar).sort());
  });
});

describe('lifecycle', () => {
  it('closes its change stream when it leaves the page', async () => {
    const iam = fakeIam(world);
    const element = mount(ElementTag.roles, iam);
    await inside(element).findByText('Reader');
    expect(iam.streams.filter((stream) => !stream.closed)).toHaveLength(1);
    element.remove();
    await waitFor(() => expect(iam.streams.every((stream) => stream.closed)).toBe(true));
  });
});
