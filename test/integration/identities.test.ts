import { randomUUID } from 'node:crypto';

import { Configuration, IdentityApi, OAuth2Api } from '@ory/client';

import { Identities } from '../../src/api/identities';
import { KratosAdmin } from '../../src/iam/kratos';

const KRATOS_ADMIN = process.env.KRATOS_ADMIN_URL || 'http://localhost:4434';
const KRATOS_PUBLIC = process.env.KRATOS_PUBLIC_URL || 'http://localhost:4433';
const HYDRA_ADMIN = process.env.HYDRA_ADMIN_URL || 'http://localhost:4445';
const HYDRA_PUBLIC = process.env.HYDRA_PUBLIC_URL || 'http://localhost:4444';

const identities = new Identities({ kratosAdmin: KRATOS_ADMIN, kratosPublic: KRATOS_PUBLIC, hydraAdmin: HYDRA_ADMIN });
const hydra = new OAuth2Api(new Configuration({ basePath: HYDRA_ADMIN }));
const kratos = new IdentityApi(new Configuration({ basePath: KRATOS_ADMIN }));

const token = async (id: string, secret: string): Promise<{ status: number; accessToken?: string }> => {
  const response = await fetch(`${HYDRA_PUBLIC}/oauth2/token`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });
  const body = (await response.json()) as { access_token?: string };
  return { status: response.status, ...(body.access_token !== undefined ? { accessToken: body.access_token } : {}) };
};

describe('people and machine clients against Kratos and Hydra', () => {
  it('creates a client that obtains a token with its own credentials, issued to it', async () => {
    const id = `client-${randomUUID()}`;
    const created = await identities.createClient({ id, name: 'integration client', audience: ['integration'] });
    expect(created?.subject).toBe(id);

    const issued = await token(id, created!.secret);
    expect(issued.status).toBe(200);
    const { data } = await hydra.introspectOAuth2Token({ token: issued.accessToken! });
    expect(data).toMatchObject({ active: true, sub: id });
    expect(await identities.createClient({ id })).toBeUndefined();

    await identities.deleteClient(id);
  });

  it('rotates a secret so the new one obtains tokens and the old one no longer does', async () => {
    const id = `client-${randomUUID()}`;
    const created = await identities.createClient({ id });
    const rotated = await identities.rotate(id);

    expect(rotated?.secret).not.toBe(created!.secret);
    expect((await token(id, rotated!.secret)).status).toBe(200);
    expect((await token(id, created!.secret)).status).toBe(401);
    expect(await identities.rotate(`missing-${randomUUID()}`)).toBeUndefined();

    await identities.deleteClient(id);
  });

  it('retires a client, and answers so for one that is already gone', async () => {
    const id = `client-${randomUUID()}`;
    await identities.createClient({ id });
    expect(await identities.deleteClient(id)).toBe(true);
    expect(await identities.deleteClient(id)).toBe(false);
  });

  it('finds or creates a person, inviting only the one it created', async () => {
    const email = `person-${randomUUID()}@example.test`;
    const first = await identities.account(email, 'Integration Person');
    expect(first).toMatchObject({ created: true, invited: true });
    expect(await identities.account(email)).toEqual({ subject: first.subject, created: false, invited: false });

    const listed = await identities.subjects();
    expect(listed).toContainEqual({ id: first.subject, kind: 'person', email, name: 'Integration Person' });

    expect(await identities.deleteAccount(first.subject)).toBe(true);
    expect(await identities.deleteAccount(first.subject)).toBe(false);
  });

  it('writes what a person holds into their public metadata, keeping what else it holds', async () => {
    const created = await kratos.createIdentity({
      createIdentityBody: {
        schema_id: 'default',
        traits: { email: `person-${randomUUID()}@example.test` },
        metadata_public: { team: 'ops' },
      },
    });
    const permissions = { 'mcm.getDFSPs': { participant: ['dfsp-a'] }, 'mcm.getHealth': {} };

    await identities.writePermissions(created.data.id, permissions);

    const { data } = await kratos.getIdentity({ id: created.data.id });
    expect(data.metadata_public).toEqual({ team: 'ops', permissions });
    await kratos.deleteIdentity({ id: created.data.id });
  });

  it('has no session to end for a person who holds none, or for an id that is no identity', async () => {
    const people = new KratosAdmin(KRATOS_ADMIN);
    await expect(people.revokeSessions(randomUUID())).resolves.toBeUndefined();
    await expect(people.revokeSessions('p4-client')).resolves.toBeUndefined();
  });
});
