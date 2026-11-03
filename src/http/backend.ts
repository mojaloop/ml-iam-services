import fastifySse from '@fastify/sse';
import Fastify, { FastifyInstance, FastifyReply, FastifyRequest, FastifyServerOptions } from 'fastify';
import openapiGlue from 'fastify-openapi-glue';
import { StatusCodes } from 'http-status-codes';

import { Logged } from '../logged';

const PLAIN_TEXT = 'text/plain; charset=utf-8';

/** What a validation error names when the request as a whole is wrong. */
const WHOLE_REQUEST = 'request';

/** Every operation streamed as server-sent events is streamed only so, with no heartbeat: a client reconnects on its own. */
const STREAMED = { kind: 'only', heartbeat: false } as const;

/** What a handler answers; `text` serves plain, `body` serves JSON, neither serves the status alone. */
export interface Answer {
  status: number;
  body?: unknown;
  text?: string;
  headers?: Record<string, string>;
}

export type Handler = (req: FastifyRequest) => Answer | Promise<Answer>;

/** An operation answered as server-sent events, through `res.sse`, for as long as the client stays. */
export interface Events {
  events: (req: FastifyRequest, res: FastifyReply) => Promise<void>;
}

/** A path parameter as the caller sent it, already decoded by the router. */
export const param = (req: FastifyRequest, name: string): string => (req.params as Record<string, string>)[name]!;

export const query = (req: FastifyRequest, name: string): string | undefined =>
  (req.query as Record<string, string | undefined>)[name];

const reply = (res: FastifyReply, answer: Answer): FastifyReply => {
  res.code(answer.status);
  if (answer.headers !== undefined) res.headers(answer.headers);
  if (answer.text !== undefined) return res.type(PLAIN_TEXT).send(answer.text);
  return res.send(answer.body);
};

/**
 * Refusals answer `{errors}` whatever refused them: the document's
 * validation, an unknown path, or a handler that failed.
 */
const answerErrors = (app: FastifyInstance): void => {
  app.setNotFoundHandler((_req, res) => res.code(StatusCodes.NOT_FOUND).send({ errors: ['Not found'] }));
  app.setErrorHandler((error: Error & { validation?: Array<{ instancePath?: string; message?: string }>; statusCode?: number }, req, res) => {
    if (error.validation !== undefined) {
      return res.code(StatusCodes.BAD_REQUEST).send({
        errors: error.validation.map((e) => `${e.instancePath || WHOLE_REQUEST} ${e.message ?? ''}`.trim()),
      });
    }
    if (error.statusCode !== undefined && error.statusCode < StatusCodes.INTERNAL_SERVER_ERROR) {
      return res.code(error.statusCode).send({ errors: [error.message] });
    }
    console.error(JSON.stringify({ event: Logged.requestFailed, path: req.url, error: String(error) }));
    return res.code(StatusCodes.INTERNAL_SERVER_ERROR).send({ errors: ['Internal server error'] });
  });
};

/**
 * A server routing and validating by a document, one handler per operation
 * it declares. A handler missing for an operation, or one for an operation
 * the document lacks, fails the start. Closing the server ends every event
 * stream it holds open, so a client reconnects to another replica instead of
 * holding this one past its stop.
 */
export async function documentServer(
  specification: string | object,
  handlers: Record<string, Handler | Events>,
  options: FastifyServerOptions & { https?: { cert: Buffer; key: Buffer } } = {},
  before?: (app: FastifyInstance) => void,
): Promise<FastifyInstance> {
  const app = Fastify({
    ...options,
    ajv: { customOptions: { coerceTypes: false, removeAdditional: false, useDefaults: false } },
  } as FastifyServerOptions);
  answerErrors(app);
  before?.(app);
  await app.register(fastifySse);

  const streams = new Set<FastifyReply>();
  app.addHook('preClose', async () => {
    for (const res of streams) res.sse.close();
  });
  const streamed = (events: Events['events']) => async (req: FastifyRequest, res: FastifyReply) => {
    streams.add(res);
    res.sse.onClose(() => streams.delete(res));
    await events(req, res);
  };

  const declared: string[] = [];
  await app.register(openapiGlue, {
    specification,
    operationResolver: (operationId: string) => {
      declared.push(operationId);
      const handle = handlers[operationId];
      if (handle === undefined) throw new Error(`the document and the handlers disagree: no handler for ${operationId}`);
      if (typeof handle !== 'function') return { sse: STREAMED, handler: streamed(handle.events) };
      return async (req: FastifyRequest, res: FastifyReply) => reply(res, await handle(req));
    },
  });
  await app.ready();

  const undeclared = Object.keys(handlers).filter((id) => !declared.includes(id));
  if (undeclared.length > 0) {
    throw new Error(`the document and the handlers disagree: no operation for [${undeclared.join(', ')}]`);
  }
  return app;
}

/** Closes every server on the signals a pod is stopped with, once `before` has finished. */
export const closeOnSignals = (servers: FastifyInstance[], before: () => void | Promise<void> = () => undefined): void => {
  const shutdown = (): void => {
    void Promise.resolve(before())
      .then(() => Promise.all(servers.map((s) => s.close())))
      .then(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
};
