import { createServer, IncomingMessage, Server } from 'node:http';
import { AddressInfo } from 'node:net';

import { applyRoles } from '../../src/iam/reconcile';
import { RolesFile } from '../../src/iam/roles';
import { MemoryKeto } from './memory-keto';

interface Seen {
  method: string;
  path: string;
  body: unknown;
}

interface CourierMessage {
  template_type: string;
  status: string;
}

/**
 * A Kratos answering the identity lookup, the creation, the courier's record
 * and the recovery flow. The record comes in pages of `pageSize`, each naming
 * the next in its Link header.
 */
function fakeKratos(
  existing: Array<{ id: string }>,
  messages: CourierMessage[] = [],
  pageSize = Infinity,
): { server: Server; seen: Seen[] } {
  const seen: Seen[] = [];
  const server = createServer((req: IncomingMessage, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString();
      const body: unknown = text === '' ? undefined : JSON.parse(text);
      seen.push({ method: req.method!, path: req.url!, body });
      res.setHeader('Content-Type', 'application/json');
      if (req.url!.startsWith('/admin/courier/messages')) {
        const from = Number(new URL(req.url!, 'http://kratos').searchParams.get('page_token') ?? 0);
        const to = Math.min(from + pageSize, messages.length);
        if (to < messages.length) res.setHeader('Link', `</admin/courier/messages?page_token=${to}>; rel="next"`);
        return res.end(JSON.stringify(messages.slice(from, to).map((m) => ({ ...m, recipient: 'admin@hub.example' }))));
      }
      if (req.url!.startsWith('/admin/identities?')) return res.end(JSON.stringify(existing));
      if (req.url! === '/admin/identities') return res.end(JSON.stringify({ id: 'created-id' }));
      if (req.url! === '/self-service/recovery/api') return res.end(JSON.stringify({ id: 'flow-1' }));
      if (req.url!.startsWith('/self-service/recovery?flow=')) return res.end(JSON.stringify({ state: 'sent_email' }));
      res.statusCode = 404;
      return res.end('{}');
    });
  });
  return { server, seen };
}

const urlOf = (server: Server): string => `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

const file: RolesFile = { roles: { 'hub-admin': { grants: [] } } };

const withKratos = async (
  fake: { server: Server; seen: Seen[] },
  run: (url: string, seen: Seen[]) => Promise<void>,
): Promise<void> => {
  await new Promise<void>((r) => fake.server.listen(0, r));
  try {
    await run(urlOf(fake.server), fake.seen);
  } finally {
    fake.server.close();
  }
};

const adminOptions = (url: string): Parameters<typeof applyRoles>[3] => ({
  admin: { email: 'admin@hub.example', role: 'hub-admin', kratosAdminUrl: url, kratosPublicUrl: url },
});

const invitationOf = (seen: Seen[]): Seen | undefined =>
  seen.find((s) => s.method === 'POST' && s.path.startsWith('/self-service/recovery?flow='));

describe('the first admin', () => {
  it('with nothing on the courier record, is created and invited by email', async () => {
    await withKratos(fakeKratos([]), async (url, seen) => {
      const applied = await applyRoles(new MemoryKeto(), file, new Map(), adminOptions(url));

      expect(applied.admin).toEqual({ email: 'admin@hub.example', id: 'created-id', created: true, invited: true });
      const creation = seen.find((s) => s.method === 'POST' && s.path === '/admin/identities');
      expect(creation?.body).not.toHaveProperty('credentials');
      expect(invitationOf(seen)?.body).toMatchObject({ method: 'link', email: 'admin@hub.example' });
    });
  });

  it('holding an invitation the courier delivered, is left alone', async () => {
    const fake = fakeKratos([{ id: 'existing-id' }], [{ template_type: 'recovery_valid', status: 'sent' }]);
    await withKratos(fake, async (url, seen) => {
      const applied = await applyRoles(new MemoryKeto(), file, new Map(), adminOptions(url));

      expect(applied.admin).toEqual({ email: 'admin@hub.example', id: 'existing-id', created: false, invited: false });
      expect(invitationOf(seen)).toBeUndefined();
    });
  });

  it('holding an invitation the courier delivered on a later page of its record, is left alone', async () => {
    const fake = fakeKratos(
      [{ id: 'existing-id' }],
      [
        { template_type: 'verification_valid', status: 'sent' },
        { template_type: 'recovery_valid', status: 'sent' },
      ],
      1,
    );
    await withKratos(fake, async (url, seen) => {
      const applied = await applyRoles(new MemoryKeto(), file, new Map(), adminOptions(url));

      expect(applied.admin?.invited).toBe(false);
      expect(invitationOf(seen)).toBeUndefined();
    });
  });

  it('with an invitation still in the courier queue, receives that one and no copy', async () => {
    const fake = fakeKratos([{ id: 'existing-id' }], [{ template_type: 'recovery_valid', status: 'queued' }]);
    await withKratos(fake, async (url, seen) => {
      const applied = await applyRoles(new MemoryKeto(), file, new Map(), adminOptions(url));

      expect(applied.admin?.invited).toBe(false);
      expect(invitationOf(seen)).toBeUndefined();
    });
  });

  it('whose invitation the courier abandoned, is invited again', async () => {
    const fake = fakeKratos([{ id: 'existing-id' }], [{ template_type: 'recovery_valid', status: 'abandoned' }]);
    await withKratos(fake, async (url, seen) => {
      const applied = await applyRoles(new MemoryKeto(), file, new Map(), adminOptions(url));

      expect(applied.admin?.invited).toBe(true);
      expect(invitationOf(seen)?.body).toMatchObject({ method: 'link', email: 'admin@hub.example' });
    });
  });

  it('sent other mail but never an invitation, is invited', async () => {
    const fake = fakeKratos([{ id: 'existing-id' }], [{ template_type: 'verification_valid', status: 'sent' }]);
    await withKratos(fake, async (url, seen) => {
      const applied = await applyRoles(new MemoryKeto(), file, new Map(), adminOptions(url));

      expect(applied.admin?.invited).toBe(true);
      expect(invitationOf(seen)?.body).toMatchObject({ method: 'link', email: 'admin@hub.example' });
    });
  });

  it('invited by a code-based deployment, is left alone', async () => {
    const fake = fakeKratos([{ id: 'existing-id' }], [{ template_type: 'recovery_code_valid', status: 'sent' }]);
    await withKratos(fake, async (url, seen) => {
      expect((await applyRoles(new MemoryKeto(), file, new Map(), adminOptions(url))).admin?.invited).toBe(false);
      expect(invitationOf(seen)).toBeUndefined();
    });
  });

  it('created with a configured password, gets it and no email', async () => {
    await withKratos(fakeKratos([]), async (url, seen) => {
      const applied = await applyRoles(new MemoryKeto(), file, new Map(), {
        admin: {
          email: 'admin@hub.example',
          role: 'hub-admin',
          kratosAdminUrl: url,
          kratosPublicUrl: url,
          password: 'configured',
        },
      });

      expect(applied.admin).toEqual({ email: 'admin@hub.example', id: 'created-id', created: true, invited: false });
      const creation = seen.find((s) => s.method === 'POST' && s.path === '/admin/identities');
      expect(creation?.body).toMatchObject({ credentials: { password: { config: { password: 'configured' } } } });
      expect(seen.filter((s) => s.path.startsWith('/self-service/'))).toEqual([]);
    });
  });

  it('holds the admin role either way', async () => {
    const fake = fakeKratos([{ id: 'existing-id' }], [{ template_type: 'recovery_valid', status: 'sent' }]);
    await withKratos(fake, async (url) => {
      const keto = new MemoryKeto();
      await applyRoles(keto, file, new Map(), {
        admin: { email: 'admin@hub.example', role: 'hub-admin', kratosAdminUrl: url },
      });
      expect(keto.tuples).toContainEqual(
        expect.objectContaining({ object: 'hub-admin', relation: 'members', subject_id: 'existing-id' }),
      );
    });
  });
});
