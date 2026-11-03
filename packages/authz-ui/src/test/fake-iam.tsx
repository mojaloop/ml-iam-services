import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import type { ReactElement } from 'react';

import { createAuthzClient } from '../client';
import { AuthzProvider } from '../react/context';

export const BASE = 'https://portal.test/iam';

export interface Recorded {
  method: string;
  path: string;
  query: URLSearchParams;
  credentials: RequestCredentials;
  contentType: string | null;
  body: unknown;
}

export interface Answer {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
}

type Handler = (request: Recorded, params: Record<string, string>) => Answer;

/**
 * A stand-in for the gateway in front of the IAM: routes keyed `METHOD /path`
 * with `:param` segments, every request recorded as it arrived.
 */
export function fakeIam(routes: Record<string, Handler | Answer>) {
  const requests: Recorded[] = [];
  const table = Object.entries(routes).map(([key, handler]) => {
    const [method, pathname] = key.split(' ') as [string, string];
    return { method, pattern: new URLPattern({ pathname: `/iam${pathname}` }), handler };
  });

  const fetch = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const text = await request.text();
    const recorded: Recorded = {
      method: request.method,
      path: url.pathname.slice('/iam'.length),
      query: url.searchParams,
      credentials: request.credentials,
      contentType: request.headers.get('content-type'),
      body: text === '' ? undefined : JSON.parse(text),
    };
    requests.push(recorded);
    for (const { method, pattern, handler } of table) {
      const match = pattern.exec({ pathname: url.pathname });
      if (method !== request.method || match === null) continue;
      const params = Object.fromEntries(
        Object.entries(match.pathname.groups).map(([name, value]) => [name, decodeURIComponent(value ?? '')]),
      );
      const { status = 200, body, headers = {} } = typeof handler === 'function' ? handler(recorded, params) : handler;
      return body === undefined
        ? new Response(null, { status, headers })
        : new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
    }
    return new Response(JSON.stringify({ errors: [`no route for ${request.method} ${url.pathname}`] }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  };

  const streams: FakeStream[] = [];
  class FakeStream extends EventTarget {
    readonly url: string;
    readonly withCredentials: boolean;
    closed = false;

    constructor(url: string | URL, init?: EventSourceInit) {
      super();
      this.url = String(url);
      this.withCredentials = init?.withCredentials ?? false;
      streams.push(this);
    }

    close() {
      this.closed = true;
    }
  }

  /** What the IAM's change stream sends each open stream when what it applied changes. */
  const announce = (etag: string) => {
    for (const stream of streams.filter((s) => !s.closed)) {
      stream.dispatchEvent(new MessageEvent('composition', { data: JSON.stringify({ etag }), lastEventId: etag }));
    }
  };

  const EventSource = FakeStream as unknown as typeof globalThis.EventSource;
  const client = createAuthzClient({ baseUrl: BASE, fetch, EventSource });
  const of = (method: string, path: string) => requests.filter((r) => r.method === method && r.path === path);
  return { client, fetch, EventSource, requests, of, streams, announce };
}

export function renderWithIam(ui: ReactElement, iam: ReturnType<typeof fakeIam>, language?: string) {
  const queries = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={queries}>
      <AuthzProvider client={iam.client} language={language}>
        {ui}
      </AuthzProvider>
    </QueryClientProvider>,
  );
}
