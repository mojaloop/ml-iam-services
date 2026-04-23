import { createServer } from 'node:http';

import request from 'supertest';

const mockFetch = jest.fn();
global.fetch = mockFetch;

jest.mock('../../src/keto-batch-auth/config', () => ({
  config: {
    port: 3000,
    ketoReadUrl: 'http://keto-read-test',
  },
}));

import { handleRequest } from '../../src/keto-batch-auth/handler';

const app = createServer((req, res) => {
  handleRequest(req, res).catch(() => {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Internal server error' }));
  });
});

describe('keto-batch-auth', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  describe('GET /health', () => {
    it('should return 200 with status ok', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({ status: 'ok' });
    });
  });

  describe('POST /', () => {
    it('should return 405 for non-POST methods', async () => {
      const response = await request(app).get('/');

      expect(response.status).toBe(405);
      expect(response.body).toEqual({ error: 'Method not allowed' });
    });

    it('should return 200 when at least one result is allowed', async () => {
      mockFetch.mockResolvedValueOnce({
        json: () => Promise.resolve({
          results: [{ allowed: false }, { allowed: true }],
        }),
      });

      const response = await request(app)
        .post('/')
        .send({ tuples: [] });

      expect(response.status).toBe(200);
      expect(response.body.authorized).toBe(true);
    });

    it('should return 403 when no results are allowed', async () => {
      mockFetch.mockResolvedValueOnce({
        json: () => Promise.resolve({
          results: [{ allowed: false }, { allowed: false }],
        }),
      });

      const response = await request(app)
        .post('/')
        .send({ tuples: [] });

      expect(response.status).toBe(403);
      expect(response.body.authorized).toBe(false);
    });

    it('should return 500 on fetch error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const response = await request(app)
        .post('/')
        .send({ tuples: [] });

      expect(response.status).toBe(500);
      expect(response.body).toEqual({ error: 'Internal server error' });
    });
  });
});
