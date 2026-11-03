import { createHash } from 'node:crypto';

import { FastifyInstance, FastifyRequest } from 'fastify';
import { StatusCodes } from 'http-status-codes';

import { Document, documentAt } from '../api/documents';
import { Header, HEALTHY, JSON_MEDIA, Param } from '../api/vocabulary';
import { accessRules, Composition as Composed } from '../authzgen/compose';
import { ServiceCatalog } from '../authzgen/types';
import { Answer, documentServer, Handler, query } from '../http/backend';
import { assignProblems, holdersOf, Named, Reach } from '../iam/holdings';
import { KetoWriter } from '../iam/keto';
import { ServedResourceName } from '../iam/own';
import { Assignment, Provisioner } from '../iam/provisioner';
import { Affected, Applied } from '../iam/reconcile';
import { RoleView, RuleView } from '../iam/role-sync';
import { indexCatalogs, RolesFile } from '../iam/roles';
import { Logged } from '../logged';
import type { Leader } from './leader';

/** What the controller serves its API process: everything it composed and applied, and what became of each object. */
export interface Composition {
  catalog: ServiceCatalog[];
  resourceNames: Record<string, ServedResourceName>;
  roles: RoleView[];
  separations: RuleView[];
  pending: string[];
  applied?: Applied;
  /** Permissions services renamed, by their old name, and the ones they removed. */
  renamed: Record<string, string>;
  removed: string[];
  /** The prefix the IAM's own route gives its public API, under which its operations are permissions. */
  servesAs?: string;
}

/** The ETag of a composition, as held since `started`: it moves with either. */
export const tagOf = (composition: Composition, started: string): string =>
  `"${createHash('sha256').update(started).update(JSON.stringify(composition)).digest('hex')}"`;

interface Write {
  subject: string;
  role: string;
  resources?: Record<string, string>;
  by?: { subject: string; roles: Named; reach: Reach };
}

export interface ControllerState {
  keto: KetoWriter;
  provisioner: Provisioner;
  exclusive: <T>(write: () => Promise<T>) => Promise<T>;
  live: () => RolesFile;
  catalog: () => ServiceCatalog[];
  composition: () => Composition;
  etag: () => string;
  composed: () => Pick<Composed, 'model' | 'derivation' | 'rules'> | undefined;
  /** Whether this replica applied the deployment's roles, before which it takes no write. */
  applied: () => boolean;
  /** Whether this replica answers: it leads and applied the roles, or it composed and stands by. */
  ready: () => boolean;
  /** Where the writes go. */
  leader: () => Leader;
  /** Ends the sessions of subjects whose permissions a write just changed. */
  revoke: (affected: Affected) => Promise<void>;
}

const STARTING = { status: StatusCodes.SERVICE_UNAVAILABLE, body: { errors: ["the controller has not applied the deployment's roles yet"] } };
const LEADERLESS = { status: StatusCodes.SERVICE_UNAVAILABLE, body: { errors: ['no controller replica leads yet'] } };

/** What a request handed on is marked with. */
const FORWARDED_ONCE = '1';

/** Hands a request to the leading replica and answers what it answered. */
async function forward(address: string, req: FastifyRequest): Promise<Answer> {
  const ifNoneMatch = req.headers[Header.ifNoneMatch];
  let response: Response;
  try {
    response = await fetch(`${address}${req.url}`, {
      method: req.method,
      headers: {
        [Header.forwarded]: FORWARDED_ONCE,
        ...(req.body !== undefined ? { [Header.contentType]: JSON_MEDIA } : {}),
        ...(typeof ifNoneMatch === 'string' ? { [Header.ifNoneMatch]: ifNoneMatch } : {}),
      },
      ...(req.body !== undefined ? { body: JSON.stringify(req.body) } : {}),
    });
  } catch (error) {
    return { status: StatusCodes.SERVICE_UNAVAILABLE, body: { errors: [`the leading replica at ${address} does not answer: ${String(error)}`] } };
  }
  const etag = response.headers.get(Header.etag);
  const text = await response.text();
  return {
    status: response.status,
    ...(text !== '' ? { body: JSON.parse(text) as unknown } : {}),
    ...(etag !== null ? { headers: { [Header.etag]: etag } } : {}),
  };
}

/**
 * The controller's API. Every assignment is checked and written inside one
 * exclusive write, so two arriving together are judged one after the other
 * against the memberships the first one left. Only the leading replica
 * writes, and only it holds the verdicts of what it applied, so a standby
 * hands those requests to it.
 */
export async function controllerApi(state: ControllerState): Promise<FastifyInstance> {
  const atLeader = (handle: Handler): Handler => async (req) => {
    const leader = state.leader();
    if (leader.self) return state.applied() ? handle(req) : STARTING;
    if (leader.address === undefined || req.headers[Header.forwarded] !== undefined) return LEADERLESS;
    return forward(leader.address, req);
  };

  const assignment = async (body: Write, granting: boolean) =>
    state.exclusive(async () => {
      const parsed: Assignment = { role: body.role, resources: body.resources ?? {} };
      const problems = await state.provisioner.problemsWith(body.subject, parsed, granting);
      const role = state.live().roles[body.role];
      if (problems.length === 0 && role !== undefined && body.by !== undefined) {
        const held = await holdersOf(state.keto, body.by.subject);
        problems.push(...assignProblems(body.role, role, parsed.resources, indexCatalogs(state.catalog()), held, body.by));
      }
      if (problems.length > 0) return { status: StatusCodes.UNPROCESSABLE_ENTITY, body: { errors: problems } };
      const result = granting
        ? await state.provisioner.assign(body.subject, parsed)
        : await state.provisioner.unassign(body.subject, parsed);
      await state.revoke({ everyone: false, subjects: [body.subject] });
      console.log(
        JSON.stringify({
          event: granting ? Logged.assign : Logged.unassign,
          subject: body.subject,
          instance: result.instance,
          by: body.by?.subject,
        }),
      );
      return { status: StatusCodes.OK, body: result };
    });

  return documentServer(documentAt(Document.controller), {
    getHealth: () => ({ status: StatusCodes.OK, body: HEALTHY }),
    getReady: () => (state.ready() ? { status: StatusCodes.OK, body: HEALTHY } : STARTING),
    getComposition: atLeader((req) => {
      const etag = state.etag();
      return req.headers[Header.ifNoneMatch] === etag
        ? { status: StatusCodes.NOT_MODIFIED, headers: { [Header.etag]: etag } }
        : { status: StatusCodes.OK, body: state.composition(), headers: { [Header.etag]: etag } };
    }),
    getDerivation: () => ({ status: StatusCodes.OK, text: state.composed()?.derivation ?? '' }),
    getAccessRules: () => ({ status: StatusCodes.OK, text: accessRules(state.composed()?.rules ?? {}) }),
    getKetoNamespaces: () => ({ status: StatusCodes.OK, text: state.composed()?.model ?? '' }),
    listResources: atLeader(async (req) => {
      const { resources, stale } = await state.provisioner.listed(query(req, Param.resourceName));
      return { status: StatusCodes.OK, body: { resources, stale } };
    }),
    writeAssignment: atLeader((req) => assignment(req.body as Write, true)),
    removeAssignment: atLeader((req) => assignment(req.body as Write, false)),
    addResource: atLeader(async (req) => {
      const ref = req.body as { resourceName: string; id: string };
      const { problem } = await state.exclusive(() => state.provisioner.provision(ref));
      if (problem !== undefined) return { status: StatusCodes.UNPROCESSABLE_ENTITY, body: { errors: [problem] } };
      console.log(JSON.stringify({ event: Logged.provision, resourceName: ref.resourceName, id: ref.id }));
      return { status: StatusCodes.OK, body: ref };
    }),
    removeResource: atLeader(async (req) => {
      const ref = req.body as { resourceName: string; id: string };
      const result = await state.exclusive(() => state.provisioner.deprovision(ref));
      if (result.problem !== undefined) return { status: StatusCodes.UNPROCESSABLE_ENTITY, body: { errors: [result.problem] } };
      await state.revoke({ everyone: false, subjects: result.members });
      console.log(JSON.stringify({ event: Logged.deprovision, resourceName: ref.resourceName, id: ref.id, orphaned: result.orphaned }));
      return { status: StatusCodes.OK, body: { orphaned: result.orphaned } };
    }),
  });
}

/** One write to the graph at a time, in the order they arrive. */
export const serially = () => {
  let tail: Promise<unknown> = Promise.resolve();
  return <T>(write: () => Promise<T>): Promise<T> => {
    const next = tail.then(write, write);
    tail = next.catch(() => undefined);
    return next;
  };
};
