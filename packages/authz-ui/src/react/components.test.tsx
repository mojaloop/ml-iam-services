import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import type { Verdict } from '../client';
import { BASE, fakeIam, renderWithIam } from '../test/fake-iam';
import { alice, auditor, holdings, reader, resources, robot, world } from '../test/world';
import { AssignmentEditor } from './AssignmentEditor';
import { ResourcePicker } from './ResourcePicker';
import { RoleEditor, type RoleEditorProps } from './RoleEditor';
import { RoleList } from './RoleList';
import { SubjectList } from './SubjectList';

describe('RoleList', () => {
  it('puts the roles every signed-in subject holds in their own section, each with its owner and verdict', async () => {
    const iam = fakeIam(world);
    renderWithIam(<RoleList />, iam);

    const everyone = await screen.findByRole('heading', { name: 'Held by every signed-in subject' });
    const everyoneSection = everyone.closest('section') as HTMLElement;
    expect(within(everyoneSection).getByText('signed-in')).toBeInTheDocument();
    expect(within(everyoneSection).queryByText('Reader')).toBeNull();

    const assignable = screen.getByRole('heading', { name: 'Roles' }).closest('section') as HTMLElement;
    expect(within(assignable).queryByText('signed-in')).toBeNull();
    const readerItem = within(assignable).getByText('Reader').closest('li') as HTMLElement;
    expect(within(readerItem).getByText('reader')).toBeInTheDocument();
    expect(within(readerItem).getByText('Reads entries')).toBeInTheDocument();
    expect(within(readerItem).getByText('Composed here')).toBeInTheDocument();
    expect(within(readerItem).getByText('Not read yet')).toBeInTheDocument();

    const auditorItem = within(assignable).getByText('auditor').closest('li') as HTMLElement;
    expect(within(auditorItem).getByText('Applied by the deployment')).toBeInTheDocument();
    expect(within(auditorItem).getByText('Refused')).toBeInTheDocument();
    expect(within(auditorItem).getByText('unknown permission')).toBeInTheDocument();
  });

  it('shows text in the language asked for, and the first entry for a language it lacks', async () => {
    const iam = fakeIam(world);
    const { unmount } = renderWithIam(<RoleList />, iam, 'uk');
    expect(await screen.findByText('Читач')).toBeInTheDocument();
    unmount();
    renderWithIam(<RoleList />, fakeIam(world), 'fr');
    expect(await screen.findByText('Reader')).toBeInTheDocument();
  });

  it('hands the chosen role to the app', async () => {
    const onSelect = vi.fn();
    renderWithIam(<RoleList onSelect={onSelect} />, fakeIam(world));
    await userEvent.click(await screen.findByRole('button', { name: 'Reader' }));
    expect(onSelect).toHaveBeenCalledWith(reader);
  });
});

describe('RoleEditor', () => {
  const openPicker = async () => {
    await userEvent.click(screen.getByRole('combobox', { name: 'Add a permission' }));
    return screen.getByRole('listbox', { name: 'Add a permission' });
  };

  const addPermission = async (summary: string) => {
    await userEvent.click(within(await openPicker()).getByRole('option', { name: new RegExp(`^${summary}`) }));
  };

  const compose = async (beforeSave?: RoleEditorProps['beforeSave']) => {
    const iam = fakeIam({ ...world, 'POST /roles': ({ body }) => ({ status: 201, body: { ...(body as object), open: [], owner: 'iam' } }) });
    const onSaved = vi.fn();
    renderWithIam(<RoleEditor onSaved={onSaved} beforeSave={beforeSave} />, iam);
    await userEvent.type(await screen.findByLabelText('Name'), 'entry-reader');
    await userEvent.type(screen.getByLabelText('Title'), 'Entry reader');
    await addPermission('Lists entries');
    return { iam, onSaved };
  };

  it('asks the app before sending the role, and keeps it unsent when the app says no', async () => {
    let allow = false;
    const beforeSave = vi.fn(() => allow);
    const { iam, onSaved } = await compose(beforeSave);
    await userEvent.click(screen.getByRole('button', { name: 'Create role' }));
    expect(beforeSave).toHaveBeenCalledWith({
      name: 'entry-reader',
      spec: { title: 'Entry reader', grants: [{ permission: 'ledger.listEntries' }] },
      create: true,
    });
    expect(iam.of('POST', '/roles')).toHaveLength(0);
    allow = true;
    await userEvent.click(screen.getByRole('button', { name: 'Create role' }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(iam.of('POST', '/roles')).toHaveLength(1);
  });

  it('offers the catalog by summary, leaving out deprecated permissions', async () => {
    renderWithIam(<RoleEditor />, fakeIam(world));
    await screen.findByLabelText('Name');
    const offered = await openPicker();
    expect(within(offered).getByRole('option', { name: /^Lists entries/ })).toBeInTheDocument();
    expect(within(offered).queryByRole('option', { name: /^Purges the ledger/ })).toBeNull();
  });

  it('finds a permission by what is typed, across summary, id and service', async () => {
    renderWithIam(<RoleEditor />, fakeIam(world));
    await screen.findByLabelText('Name');
    const picker = screen.getByRole('combobox', { name: 'Add a permission' });
    await userEvent.type(picker, 'assignRole');
    const offered = screen.getByRole('listbox', { name: 'Add a permission' });
    expect(within(offered).getByRole('option', { name: /^Gives a subject a role/ })).toBeInTheDocument();
    expect(within(offered).queryByRole('option', { name: /^Lists entries/ })).toBeNull();
    await userEvent.clear(picker);
    await userEvent.type(picker, 'ledger');
    expect(within(offered).getByRole('option', { name: /^Lists entries/ })).toBeInTheDocument();
    expect(within(offered).queryByRole('option', { name: /^Gives a subject a role/ })).toBeNull();
  });

  it('offers each permission once, since a role gives a permission with one reach', async () => {
    await compose();
    expect(within(await openPicker()).queryByRole('option', { name: /^Lists entries/ })).toBeNull();
  });

  it('checks the name as it is typed', async () => {
    renderWithIam(<RoleEditor />, fakeIam(world));
    const name = await screen.findByLabelText('Name');
    expect(name).toHaveAttribute('aria-invalid', 'false');
    await userEvent.type(name, 'Not Valid');
    expect(name).toHaveAttribute('aria-invalid', 'true');
    expect(name).toHaveAccessibleDescription(
      'Lowercase letters, digits and "-", starting and ending with a letter or digit, at most 63',
    );
    await userEvent.clear(name);
    await userEvent.type(name, 'entry-reader');
    expect(name).toHaveAttribute('aria-invalid', 'false');
    await userEvent.clear(name);
    await userEvent.tab();
    expect(name).toHaveAttribute('aria-invalid', 'true');
    expect(name).toHaveAccessibleDescription('Name the role');
  });

  it('composes a role whose grant leaves its resource name open for the assignment', async () => {
    const { iam, onSaved } = await compose();
    await userEvent.click(screen.getByRole('button', { name: 'Create role' }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(iam.of('POST', '/roles')[0]?.body).toEqual({
      name: 'entry-reader',
      title: 'Entry reader',
      grants: [{ permission: 'ledger.listEntries' }],
    });
  });

  it('grants over all of a resource name services create, and offers none of its ids', async () => {
    const { iam, onSaved } = await compose();
    const scope = screen.getByRole('group', { name: 'Participant' });
    expect(within(scope).queryByLabelText('Specific')).toBeNull();
    await userEvent.click(within(scope).getByLabelText('All'));
    await userEvent.click(screen.getByRole('button', { name: 'Create role' }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
    expect(iam.of('POST', '/roles')[0]?.body).toMatchObject({
      grants: [{ permission: 'ledger.listEntries', resources: { participant: '$all' } }],
    });
  });

  it('names the ids chosen of the IAM’s own resource names', async () => {
    const { iam, onSaved } = await compose();
    await addPermission('Gives a subject a role');
    const scope = screen.getByRole('group', { name: 'Role' });
    await userEvent.click(within(scope).getByLabelText('Specific'));
    expect(within(scope).getByText('Choose at least one role')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create role' })).toBeDisabled();
    await userEvent.click(await within(scope).findByLabelText('reader'));
    expect(within(scope).queryByText('Choose at least one role')).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'Create role' }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
    expect(iam.of('POST', '/roles')[0]?.body).toMatchObject({
      grants: [{ permission: 'iam.assignRole', resources: { role: ['reader'] } }, { permission: 'ledger.listEntries' }],
    });
  });

  it('refuses to send a name the IAM would refuse, or a role without grants', async () => {
    const iam = fakeIam(world);
    renderWithIam(<RoleEditor />, iam);
    await userEvent.type(await screen.findByLabelText('Name'), 'Not Valid');
    expect(screen.getByRole('button', { name: 'Create role' })).toBeDisabled();
    expect(screen.getByText('A role needs at least one grant')).toBeInTheDocument();
  });

  it('changes a role the IAM owns by its name, without sending the name', async () => {
    const iam = fakeIam({ ...world, 'PUT /roles/:role': ({ body }) => ({ body: { ...reader, ...(body as object) } }) });
    const onSaved = vi.fn();
    renderWithIam(<RoleEditor role={reader} onSaved={onSaved} />, iam);
    const title = await screen.findByLabelText('Title');
    expect(title).toHaveValue('Reader');
    await userEvent.clear(title);
    await userEvent.type(title, 'Entry reader');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(iam.of('PUT', '/roles/reader')[0]?.body).toEqual({
      title: { en: 'Entry reader', uk: 'Читач' },
      description: 'Reads entries',
      grants: [{ permission: 'ledger.listEntries' }],
    });
  });

  it('shows a role the deployment applied without offering to change it', async () => {
    renderWithIam(<RoleEditor role={auditor} allowDelete />, fakeIam(world));
    expect(
      await screen.findByText('This role is applied by the deployment and changes where the deployment keeps it.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('textbox')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Delete role' })).toBeNull();
    expect(screen.getByText('All')).toBeInTheDocument();
  });

  it("shows the IAM's reasons when it refuses the role", async () => {
    const iam = fakeIam({ ...world, 'POST /roles': { status: 422, body: { errors: ['you do not hold ledger.listEntries'] } } });
    renderWithIam(<RoleEditor />, iam);
    await userEvent.type(await screen.findByLabelText('Name'), 'entry-reader');
    await addPermission('Lists entries');
    await userEvent.click(screen.getByRole('button', { name: 'Create role' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('you do not hold ledger.listEntries');
  });

  it('deletes a role only once the deletion is confirmed', async () => {
    const iam = fakeIam({ ...world, 'DELETE /roles/:role': { status: 204 } });
    const onDeleted = vi.fn();
    renderWithIam(<RoleEditor role={reader} allowDelete onDeleted={onDeleted} />, iam);
    await userEvent.click(await screen.findByRole('button', { name: 'Delete role' }));
    expect(iam.of('DELETE', '/roles/reader')).toHaveLength(0);
    await userEvent.click(screen.getByRole('button', { name: 'Delete, and take it from everyone who holds it' }));
    await waitFor(() => expect(onDeleted).toHaveBeenCalledWith('reader'));
    expect(iam.of('DELETE', '/roles/reader')).toHaveLength(1);
  });
});

describe('the change stream', () => {
  it('shows a verdict the IAM reaches after the list loaded, as soon as the IAM streams the change', async () => {
    let ready: Verdict = { reason: 'Waiting', message: 'waits for ledger' };
    const iam = fakeIam({ ...world, 'GET /roles': () => ({ body: [{ ...reader, ready }] }) });
    renderWithIam(<RoleList />, iam);
    const item = (await screen.findByText('Reader')).closest('li') as HTMLElement;
    expect(within(item).getByText('Waiting')).toBeInTheDocument();

    ready = { reason: 'Accepted' };
    await act(async () => iam.announce('"2"'));
    expect(await within(item).findByText('Accepted')).toBeInTheDocument();
  });

  it('opens one stream with the session cookie for every list and editor on the page, and closes it with the last', async () => {
    const iam = fakeIam(world);
    const { unmount } = renderWithIam(
      <>
        <RoleList />
        <RoleEditor />
      </>,
      iam,
    );
    await screen.findByText('Reader');
    expect(iam.streams).toHaveLength(1);
    expect(iam.streams[0]).toMatchObject({ url: `${BASE}/changes`, withCredentials: true, closed: false });
    unmount();
    expect(iam.streams[0]?.closed).toBe(true);
  });
});

describe('ResourcePicker', () => {
  const picker = (headers: Record<string, string>) =>
    renderWithIam(
      <ResourcePicker resourceName="participant" value={[]} onChange={() => undefined} />,
      fakeIam({ ...world, 'GET /resources': { body: resources.participant, headers } }),
    );

  it("says the list may be out of date when the IAM answered its resource name from the source's last good read", async () => {
    picker({ 'stale-sources': 'dfsp,participant' });
    await screen.findByLabelText('Participant');
    expect(screen.getByRole('status')).toHaveTextContent('This list may be out of date');
  });

  it('says nothing of the kind when only another resource name is stale', async () => {
    picker({ 'stale-sources': 'dfsp' });
    await screen.findByLabelText('Participant');
    expect(screen.queryByRole('status')).toBeNull();
  });
});

describe('AssignmentEditor', () => {
  it('lists what the subject holds, the roles every signed-in subject holds without a way to remove them', async () => {
    const iam = holdings([
      { role: 'reader', resources: { participant: 'p1' }, through: 'assigned' },
      { role: 'signed-in', resources: {}, through: 'authenticated' },
    ]);
    renderWithIam(<AssignmentEditor subject="alice" />, iam);
    const held = within((await screen.findByRole('heading', { name: 'Holds' })).closest('section') as HTMLElement);
    const readerItem = held.getByText('Reader').closest('li') as HTMLElement;
    expect(within(readerItem).getByText('Participant')).toBeInTheDocument();
    expect(within(readerItem).getByText('p1')).toBeInTheDocument();
    expect(within(readerItem).getByRole('button', { name: 'Remove' })).toBeInTheDocument();
    const everyone = held.getByText('signed-in').closest('li') as HTMLElement;
    expect(within(everyone).queryByRole('button')).toBeNull();
    expect(within(everyone).getByText('Every signed-in subject holds this')).toBeInTheDocument();
  });

  it('assigns a role over one resource per resource name it leaves open, never offering a role everyone holds', async () => {
    const iam = holdings([]);
    renderWithIam(<AssignmentEditor subject="alice" />, iam);
    const choose = await screen.findByLabelText('Role');
    expect(within(choose).queryByRole('option', { name: 'signed-in' })).toBeNull();
    await userEvent.selectOptions(choose, 'Reader');
    const assign = screen.getByRole('button', { name: 'Assign' });
    expect(assign).toBeDisabled();
    await userEvent.selectOptions(await screen.findByLabelText('Participant'), 'p2');
    await userEvent.click(assign);
    await waitFor(() =>
      expect(iam.of('POST', '/subjects/alice/assignments')[0]?.body).toEqual({
        role: 'reader',
        resources: { participant: 'p2' },
      }),
    );
    expect(await screen.findByRole('button', { name: 'Remove' })).toBeInTheDocument();
  });

  it('takes an assigned role away with the resources it was held over', async () => {
    const iam = holdings([{ role: 'reader', resources: { participant: 'p1' }, through: 'assigned' }]);
    renderWithIam(<AssignmentEditor subject="alice" />, iam);
    await userEvent.click(await screen.findByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(screen.getByText('Holds no role')).toBeInTheDocument());
    expect(iam.of('DELETE', '/subjects/alice/assignments')[0]?.body).toEqual({
      role: 'reader',
      resources: { participant: 'p1' },
    });
  });

  it('offers neither change to a caller the app says may not make them', async () => {
    renderWithIam(
      <AssignmentEditor subject="alice" canAssign={false} canUnassign={false} />,
      holdings([{ role: 'reader', resources: { participant: 'p1' }, through: 'assigned' }]),
    );
    await screen.findByText('Reader');
    expect(screen.queryByRole('button')).toBeNull();
    expect(screen.queryByLabelText('Role')).toBeNull();
  });

  it('tells the app each change once the IAM has accepted it', async () => {
    const onChanged = vi.fn();
    renderWithIam(<AssignmentEditor subject="alice" onChanged={onChanged} />, holdings([]));
    await userEvent.selectOptions(await screen.findByLabelText('Role'), 'Reader');
    await userEvent.selectOptions(await screen.findByLabelText('Participant'), 'p1');
    await userEvent.click(screen.getByRole('button', { name: 'Assign' }));
    await waitFor(() =>
      expect(onChanged).toHaveBeenCalledWith({
        subject: 'alice',
        assignment: { role: 'reader', resources: { participant: 'p1' } },
        change: 'assigned',
      }),
    );
    await userEvent.click(await screen.findByRole('button', { name: 'Remove' }));
    await waitFor(() =>
      expect(onChanged).toHaveBeenLastCalledWith({
        subject: 'alice',
        assignment: { role: 'reader', resources: { participant: 'p1' } },
        change: 'unassigned',
      }),
    );
  });
});

describe('SubjectList', () => {
  it('lists people and machine clients by name, email and kind, and hands the chosen one to the app', async () => {
    const onSelect = vi.fn();
    renderWithIam(<SubjectList onSelect={onSelect} />, fakeIam(world));
    const person = (await screen.findByRole('button', { name: 'Alice' })).closest('tr') as HTMLElement;
    expect(within(person).getByText('alice@example.test')).toBeInTheDocument();
    expect(within(person).getByText('Person')).toBeInTheDocument();
    const client = screen.getByRole('button', { name: 'robot' }).closest('tr') as HTMLElement;
    expect(within(client).getByText('Machine client')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Alice' }));
    expect(onSelect).toHaveBeenCalledWith(alice);
  });

  it('shows a page at a time', async () => {
    const many = Array.from({ length: 5 }, (_, i) => ({ ...robot, id: `robot-${i}` }));
    renderWithIam(<SubjectList pageSize={2} />, fakeIam({ ...world, 'GET /subjects': { body: many } }));
    expect(await screen.findByText('robot-0')).toBeInTheDocument();
    expect(screen.queryByText('robot-2')).toBeNull();
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText('robot-4')).toBeInTheDocument();
    expect(screen.queryByText('robot-0')).toBeNull();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
  });
});
