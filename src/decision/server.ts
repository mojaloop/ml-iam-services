import { formatScope, Scope, scopeHeaders } from '@mojaloop/authz/gateway';
import Fastify, { FastifyInstance, FastifyReply } from 'fastify';
import { StatusCodes } from 'http-status-codes';

import { HEALTHY } from '../api/vocabulary';
import { ALL_INTERFACES } from '../http/address';
import { KetoReader, KetoReads } from '../iam/keto';
import { Logged } from '../logged';
import { config } from './config';
import { decide, NO_SCOPE } from './decide';
import { parsePayload } from './payload';

/** Why a request was denied before Keto gave a verdict. */
const Denied = { payload: 'payload', keto: 'keto' } as const;

const HEALTH_PATH = '/health';
const ANY_PATH = '/*';
const ANY_CONTENT = '*';
const AS_TEXT = 'string';

/** The single audit point: one record per decision, whichever way it went. */
const audit = (record: Record<string, unknown>): void => {
  console.log(JSON.stringify({ event: Logged.decision, ...record }));
};

const answer = (res: FastifyReply, allowed: boolean, scope: Scope): FastifyReply =>
  res
    .code(allowed ? StatusCodes.OK : StatusCodes.FORBIDDEN)
    .headers(scopeHeaders(scope))
    .send({ allowed });

async function decideOn(raw: string, res: FastifyReply, keto: KetoReader): Promise<FastifyReply> {
  let payload;
  try {
    payload = parsePayload(JSON.parse(raw));
  } catch {
    payload = undefined;
  }
  if (payload === undefined) {
    audit({ allowed: false, reason: Denied.payload });
    return answer(res, false, NO_SCOPE);
  }

  try {
    const decision = await decide(payload, keto);
    for (const tuple of decision.violations) {
      console.error(
        JSON.stringify({
          event: Logged.policyViolation,
          reason: 'grant written to a user instead of a role',
          tuple,
        }),
      );
    }
    const rows = [...decision.scope.values()].reduce((n, visible) => n + visible.ids.length, 0);
    if (rows > config.scopeAlarm) {
      console.error(JSON.stringify({ event: Logged.scopeAlarm, rows, subject: payload.checks[0]!.subject_id }));
    }
    audit({
      allowed: decision.allowed,
      subject: payload.checks[0]!.subject_id,
      checks: payload.checks.map((c) => `${c.namespace}:${c.object}#${c.relation}`),
      scope: formatScope(decision.scope),
    });
    return answer(res, decision.allowed, decision.scope);
  } catch (error) {
    // Keto is the only source of a verdict, so it being unreachable is a denial.
    console.error(JSON.stringify({ event: Logged.decisionError, error: String(error) }));
    audit({ allowed: false, reason: Denied.keto });
    return answer(res, false, NO_SCOPE);
  }
}

/** Every body is read as text, so a payload that is not JSON is a denial like any other unreadable one. */
export function buildServer(keto: KetoReader = new KetoReads(config.ketoReadUrl)): FastifyInstance {
  const app = Fastify();
  app.removeAllContentTypeParsers();
  app.addContentTypeParser(ANY_CONTENT, { parseAs: AS_TEXT }, (_req, body, done) => done(null, body));
  app.get(HEALTH_PATH, async () => HEALTHY);
  app.post(ANY_PATH, async (req, res) => decideOn(typeof req.body === 'string' ? req.body : '', res, keto));
  app.setNotFoundHandler((_req, res) => res.code(StatusCodes.METHOD_NOT_ALLOWED).send({ error: 'Method not allowed' }));
  app.setErrorHandler((error, _req, res) => {
    console.error(JSON.stringify({ event: Logged.decisionError, error: String(error) }));
    return answer(res, false, NO_SCOPE);
  });
  return app;
}

export async function start(): Promise<void> {
  const app = buildServer();
  await app.listen({ port: config.port, host: ALL_INTERFACES });
  console.log(`Decision endpoint listening on port ${config.port}, checking against ${config.ketoReadUrl}`);
  const shutdown = (): void => {
    void app.close().then(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
