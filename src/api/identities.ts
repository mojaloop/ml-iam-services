import { randomBytes } from 'node:crypto';

import { Configuration, OAuth2Api } from '@ory/client';
import { StatusCodes } from 'http-status-codes';

import { InvitationState, KratosAdmin, nextPage, SessionPermissions } from '../iam/kratos';

/** What holds roles: a person signing in, or a machine client using its own credentials. */
export const SubjectKind = { person: 'person', client: 'client' } as const;
export type SubjectKind = (typeof SubjectKind)[keyof typeof SubjectKind];

export interface Subject {
  id: string;
  kind: SubjectKind;
  name?: string;
  email?: string;
}

export interface ClientSecret {
  subject: string;
  secret: string;
}

/** How a machine client gets a token, and proves who it is when it does. */
const CLIENT = { grant: 'client_credentials', auth: 'client_secret_basic' } as const;

/** The JSON patch that replaces a client's secret. */
const REPLACE_SECRET = { op: 'replace', path: '/client_secret' } as const;

const LINK = 'link';
const SECRET_BYTES = 32;

const status = (error: unknown): number | undefined => (error as { response?: { status?: number } }).response?.status;

const secret = (): string => randomBytes(SECRET_BYTES).toString('base64url');

/**
 * The people and machine clients that hold roles: Kratos identities and
 * Hydra OAuth2 clients, created and retired here and nowhere else.
 */
export class Identities {
  private readonly people: KratosAdmin;
  private readonly clients: OAuth2Api;

  constructor(urls: { kratosAdmin: string; kratosPublic: string; hydraAdmin: string }) {
    this.people = new KratosAdmin(urls.kratosAdmin, urls.kratosPublic);
    this.clients = new OAuth2Api(new Configuration({ basePath: urls.hydraAdmin }));
  }

  /** What a person holds, written where their session carries it. */
  async writePermissions(subject: string, permissions: SessionPermissions): Promise<void> {
    await this.people.writePermissions(subject, permissions);
  }

  async subjects(): Promise<Subject[]> {
    const people = (await this.people.list()).map((p): Subject => ({ ...p, kind: SubjectKind.person }));
    const machines: Subject[] = [];
    let pageToken: string | undefined;
    do {
      const { data, headers } = await this.clients.listOAuth2Clients(pageToken !== undefined ? { pageToken } : {});
      for (const client of data) {
        if (client.client_id === undefined) continue;
        machines.push({
          id: client.client_id,
          kind: SubjectKind.client,
          ...(client.client_name !== undefined && client.client_name !== '' ? { name: client.client_name } : {}),
        });
      }
      pageToken = nextPage(headers[LINK] as string | undefined);
    } while (pageToken !== undefined);
    return [...people, ...machines];
  }

  /** Finds or creates a person, inviting one just created by email to set a password. */
  async account(email: string, name?: string): Promise<{ subject: string; created: boolean; invited: boolean }> {
    const { id, created } = await this.people.findOrCreate(email, undefined, name);
    const invited = created && (await this.people.invitationState(email)) === InvitationState.none;
    if (invited) await this.people.invite(email);
    return { subject: id, created, invited };
  }

  deleteAccount(subject: string): Promise<boolean> {
    return this.people.delete(subject);
  }

  /** A client that obtains tokens with its own credentials; undefined when the id is taken. */
  async createClient(request: { id?: string; name?: string; audience?: string[] }): Promise<ClientSecret | undefined> {
    const clientSecret = secret();
    try {
      const { data } = await this.clients.createOAuth2Client({
        oAuth2Client: {
          ...(request.id !== undefined ? { client_id: request.id } : {}),
          ...(request.name !== undefined ? { client_name: request.name } : {}),
          client_secret: clientSecret,
          grant_types: [CLIENT.grant],
          response_types: [],
          token_endpoint_auth_method: CLIENT.auth,
          ...(request.audience !== undefined ? { audience: request.audience } : {}),
        },
      });
      return { subject: data.client_id!, secret: clientSecret };
    } catch (error) {
      if (status(error) === StatusCodes.CONFLICT) return undefined;
      throw error;
    }
  }

  /** A new secret for a client; undefined when there is no such client. */
  async rotate(subject: string): Promise<ClientSecret | undefined> {
    const clientSecret = secret();
    try {
      await this.clients.patchOAuth2Client({ id: subject, jsonPatch: [{ ...REPLACE_SECRET, value: clientSecret }] });
      return { subject, secret: clientSecret };
    } catch (error) {
      if (status(error) === StatusCodes.NOT_FOUND) return undefined;
      throw error;
    }
  }

  async deleteClient(subject: string): Promise<boolean> {
    try {
      await this.clients.deleteOAuth2Client({ id: subject });
      return true;
    } catch (error) {
      if (status(error) === StatusCodes.NOT_FOUND) return false;
      throw error;
    }
  }
}
