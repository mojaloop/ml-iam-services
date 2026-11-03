import { describe, expect, it } from 'vitest';

import { AuthzError } from './client';
import { BASE, fakeIam } from './test/fake-iam';

const role = { name: 'reader', grants: [{ permission: 'ledger.listEntries' }], open: [], owner: 'iam' };

describe('the client', () => {
  it('sends the browser session cookie with every request, under the base path', async () => {
    const iam = fakeIam({ 'GET /roles': { body: [role] } });
    expect(await iam.client.listRoles()).toEqual([role]);
    expect(iam.requests).toMatchObject([{ method: 'GET', path: '/roles', credentials: 'include' }]);
  });

  it('asks for the resources of one resource name, or of all', async () => {
    const iam = fakeIam({ 'GET /resources': { body: [] } });
    await iam.client.listResources('participant');
    await iam.client.listResources();
    expect(iam.requests.map((r) => r.query.get('resourceName'))).toEqual(['participant', null]);
  });

  it('names the resource names the IAM answered from their last good read', async () => {
    const resource = { resourceName: 'participant', id: 'p1' };
    const stale = fakeIam({ 'GET /resources': { body: [resource], headers: { 'stale-sources': 'participant,dfsp' } } });
    expect(await stale.client.listResources()).toEqual({ resources: [resource], stale: ['participant', 'dfsp'] });
    const fresh = fakeIam({ 'GET /resources': { body: [resource] } });
    expect(await fresh.client.listResources()).toEqual({ resources: [resource], stale: [] });
  });

  it('encodes a subject id into its path', async () => {
    const iam = fakeIam({ 'GET /subjects/:subject/assignments': { body: [] } });
    await iam.client.getAssignments('client/a b');
    expect(iam.requests[0]?.path).toBe('/subjects/client%2Fa%20b/assignments');
  });

  it('writes a role as JSON, and changes one by its name', async () => {
    const iam = fakeIam({
      'POST /roles': { status: 201, body: role },
      'PUT /roles/:role': { body: role },
    });
    await iam.client.createRole({ name: 'reader', grants: [{ permission: 'ledger.listEntries' }] });
    await iam.client.updateRole('reader', { title: 'Reader', grants: [{ permission: 'ledger.listEntries' }] });
    expect(iam.requests).toMatchObject([
      {
        method: 'POST',
        path: '/roles',
        contentType: 'application/json',
        body: { name: 'reader', grants: [{ permission: 'ledger.listEntries' }] },
      },
      { method: 'PUT', path: '/roles/reader', body: { title: 'Reader', grants: [{ permission: 'ledger.listEntries' }] } },
    ]);
  });

  it('assigns and takes away a role with the assignment in the body', async () => {
    const iam = fakeIam({
      'POST /subjects/:subject/assignments': { body: { instance: 'reader-p1' } },
      'DELETE /subjects/:subject/assignments': { body: { instance: 'reader-p1' } },
    });
    const assignment = { role: 'reader', resources: { participant: 'p1' } };
    expect(await iam.client.assignRole('alice', assignment)).toEqual({ instance: 'reader-p1' });
    await iam.client.unassignRole('alice', assignment);
    expect(iam.requests).toMatchObject([
      { method: 'POST', path: '/subjects/alice/assignments', body: assignment },
      { method: 'DELETE', path: '/subjects/alice/assignments', body: assignment },
    ]);
  });

  it('answers nothing for a deleted role', async () => {
    const iam = fakeIam({ 'DELETE /roles/:role': { status: 204 } });
    await expect(iam.client.deleteRole('reader')).resolves.toBeUndefined();
  });

  it("surfaces the IAM's reasons for a refusal", async () => {
    const iam = fakeIam({ 'POST /roles': { status: 422, body: { errors: ['reader: unknown permission x.y'] } } });
    const refusal = await iam.client.createRole({ name: 'reader', grants: [{ permission: 'x.y' }] }).catch((e) => e);
    expect(refusal).toBeInstanceOf(AuthzError);
    expect(refusal).toMatchObject({ status: 422, errors: ['reader: unknown permission x.y'] });
  });

  it('streams the composition changes with the session cookie, until closed', () => {
    const iam = fakeIam({});
    const etags: string[] = [];
    const close = iam.client.watchChanges({ onChange: (etag) => etags.push(etag) });
    expect(iam.streams[0]).toMatchObject({ url: `${BASE}/changes`, withCredentials: true });
    iam.announce('"7"');
    expect(etags).toEqual(['"7"']);
    close();
    expect(iam.streams[0]?.closed).toBe(true);
  });

  it('tells a refusal that carries no reasons by its status', async () => {
    const iam = fakeIam({ 'GET /roles': { status: 403 } });
    const refusal = await iam.client.listRoles().catch((e) => e);
    expect(refusal).toMatchObject({ status: 403, errors: [] });
    expect((refusal as Error).message).toMatch(/^403/);
  });
});
