import Fastify, { FastifyInstance } from 'fastify';

import { Feed } from '../../src/api/server';
import type { Composition } from '../../src/controller/api';

const composition = (pending: string[]): Composition => ({
  catalog: [],
  resourceNames: {},
  roles: [],
  separations: [],
  pending,
  renamed: {},
  removed: [],
});

describe('the composition feed', () => {
  let controller: FastifyInstance;
  let url: string;
  let served = { etag: '"a"', body: composition([]) };

  beforeAll(async () => {
    controller = Fastify();
    controller.get('/composition', async (req, res) =>
      req.headers['if-none-match'] === served.etag
        ? res.code(304).header('etag', served.etag).send()
        : res.header('etag', served.etag).send(served.body),
    );
    await controller.listen({ port: 0, host: '127.0.0.1' });
    url = `http://127.0.0.1:${(controller.server.address() as { port: number }).port}`;
  });

  afterAll(() => controller.close());

  it('tells each listener the ETag of every new composition it reads, once', async () => {
    const feed = new Feed(url);
    const told: string[] = [];
    feed.onChange((etag) => told.push(etag));

    served = { etag: '"a"', body: composition([]) };
    await feed.read();
    await feed.read();
    served = { etag: '"b"', body: composition(['role r waits for ledger']) };
    await feed.read();

    expect(told).toEqual(['"a"', '"b"']);
    expect(feed.etag).toBe('"b"');
    expect(feed.now().pending).toEqual(['role r waits for ledger']);
  });

  it('stops telling a listener that left', async () => {
    const feed = new Feed(url);
    const told: string[] = [];
    const leave = feed.onChange((etag) => told.push(etag));

    served = { etag: '"c"', body: composition([]) };
    await feed.read();
    leave();
    served = { etag: '"d"', body: composition([]) };
    await feed.read();

    expect(told).toEqual(['"c"']);
  });
});
