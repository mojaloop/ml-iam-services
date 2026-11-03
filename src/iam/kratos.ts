import { Configuration, CourierApi, CourierMessageStatus, FrontendApi, IdentityApi } from '@ory/client';
import { StatusCodes } from 'http-status-codes';
import parseLinkHeader from 'parse-link-header';

const LINK = 'link';
const Page = { next: 'next', token: 'page_token' } as const;

/** The token of the page a Link header names as next, absent on the last page. */
export const nextPage = (link: string | undefined): string | undefined => parseLinkHeader(link ?? null)?.[Page.next]?.[Page.token];

/** What the courier's record says about invitations to an address. */
export const InvitationState = { delivered: 'delivered', sending: 'sending', none: 'none' } as const;
export type InvitationState = (typeof InvitationState)[keyof typeof InvitationState];

const INVITATION_TEMPLATES = ['recovery_valid', 'recovery_code_valid'];

/** Every identity's traits follow this schema. */
const SCHEMA = 'default';

/** An address the IAM creates an identity with is one it vouches for. */
const VERIFIED = { via: 'email', verified: true, status: 'completed' } as const;

/** How an invitation reaches its address: a one-time recovery link. */
const RECOVERY_METHOD = 'link';

/** The most courier messages one read asks for. */
const COURIER_PAGE = 250;

/** What a person holds, as their session carries it: per permission, the ids or `$all` of each resource name it is scoped by. */
export type SessionPermissions = Record<string, Record<string, string | string[]>>;

/** The key in an identity's public metadata the permissions are written under. */
export const PERMISSIONS_KEY = 'permissions';

const METADATA_PUBLIC = '/metadata_public';
const ADD = 'add';

/** A revoke Kratos answers with: no session left (404), or an id that is no identity's (400). */
const NO_SESSION: number[] = [StatusCodes.NOT_FOUND, StatusCodes.BAD_REQUEST];

const status = (error: unknown): number | undefined => (error as { response?: { status?: number } }).response?.status;

/** Kratos' APIs, for the one identity a fresh deployment needs. */
export class KratosAdmin {
  private readonly identities: IdentityApi;
  private readonly courier: CourierApi;
  private readonly frontend?: FrontendApi;

  constructor(adminUrl: string, publicUrl?: string) {
    this.identities = new IdentityApi(new Configuration({ basePath: adminUrl }));
    this.courier = new CourierApi(new Configuration({ basePath: adminUrl }));
    if (publicUrl !== undefined) {
      this.frontend = new FrontendApi(new Configuration({ basePath: publicUrl }));
    }
  }

  async findByEmail(email: string): Promise<string | undefined> {
    const { data } = await this.identities.listIdentities({ credentialsIdentifier: email });
    return data[0]?.id;
  }

  async create(email: string, password?: string, name?: string): Promise<string> {
    const { data } = await this.identities.createIdentity({
      createIdentityBody: {
        schema_id: SCHEMA,
        traits: { email, ...(name !== undefined ? { name } : {}) },
        ...(password !== undefined ? { credentials: { password: { config: { password } } } } : {}),
        verifiable_addresses: [{ value: email, ...VERIFIED }],
      },
    });
    return data.id;
  }

  async findOrCreate(email: string, password?: string, name?: string): Promise<{ id: string; created: boolean }> {
    const existing = await this.findByEmail(email);
    if (existing !== undefined) return { id: existing, created: false };
    return { id: await this.create(email, password, name), created: true };
  }

  /** Every identity, following the pages Kratos links to. */
  async list(): Promise<Array<{ id: string; email?: string; name?: string }>> {
    const people: Array<{ id: string; email?: string; name?: string }> = [];
    let pageToken: string | undefined;
    do {
      const { data, headers } = await this.identities.listIdentities(pageToken !== undefined ? { pageToken } : {});
      for (const identity of data) {
        const traits = (identity.traits ?? {}) as { email?: string; name?: string };
        people.push({
          id: identity.id,
          ...(traits.email !== undefined ? { email: traits.email } : {}),
          ...(traits.name !== undefined ? { name: traits.name } : {}),
        });
      }
      pageToken = nextPage(headers[LINK] as string | undefined);
    } while (pageToken !== undefined);
    return people;
  }

  /** Answers false when there was nobody to delete. */
  async delete(id: string): Promise<boolean> {
    try {
      await this.identities.deleteIdentity({ id });
      return true;
    } catch (error) {
      if ((error as { response?: { status?: number } }).response?.status === StatusCodes.NOT_FOUND) return false;
      throw error;
    }
  }

  /** Writes what a person holds into their public metadata, keeping whatever else it holds. */
  async writePermissions(id: string, permissions: SessionPermissions): Promise<void> {
    const { data } = await this.identities.getIdentity({ id });
    const metadata = (data.metadata_public ?? {}) as Record<string, unknown>;
    await this.identities.patchIdentity({
      id,
      jsonPatch: [{ op: ADD, path: METADATA_PUBLIC, value: { ...metadata, [PERMISSIONS_KEY]: permissions } }],
    });
  }

  /** Ends every session of a subject; one with no session, or that is no identity, has none to end. */
  async revokeSessions(id: string): Promise<void> {
    try {
      await this.identities.deleteIdentitySessions({ id });
    } catch (error) {
      if (!NO_SESSION.includes(status(error) ?? 0)) throw error;
    }
  }

  /**
   * Kratos marks a message sent once the mail server has taken it, keeps the
   * record afterwards, and returns a message it could not hand over to the
   * queue until it either goes out or is abandoned.
   */
  async invitationState(email: string): Promise<InvitationState> {
    let sending = false;
    let pageToken: string | undefined;
    do {
      const { data, headers } = await this.courier.listCourierMessages({
        recipient: email,
        pageSize: COURIER_PAGE,
        ...(pageToken !== undefined ? { pageToken } : {}),
      });
      const invitations = data.filter((message) => INVITATION_TEMPLATES.includes(message.template_type));
      if (invitations.some((message) => message.status === CourierMessageStatus.Sent)) return InvitationState.delivered;
      sending ||= invitations.some(
        (message) => message.status === CourierMessageStatus.Queued || message.status === CourierMessageStatus.Processing,
      );
      pageToken = nextPage(headers[LINK] as string | undefined);
    } while (pageToken !== undefined);
    return sending ? InvitationState.sending : InvitationState.none;
  }

  /**
   * A self-service recovery flow for the identity: the courier emails a
   * one-time link, and clicking it signs the holder in to set a password.
   */
  async invite(email: string): Promise<void> {
    if (this.frontend === undefined) throw new Error(`no Kratos public URL to invite ${email} through`);
    const { data: flow } = await this.frontend.createNativeRecoveryFlow();
    await this.frontend.updateRecoveryFlow({
      flow: flow.id,
      updateRecoveryFlowBody: { method: RECOVERY_METHOD, email },
    });
  }
}
