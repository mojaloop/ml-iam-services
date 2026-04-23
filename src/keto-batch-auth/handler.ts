import { IncomingMessage, ServerResponse } from 'node:http';

import { config } from './config';

interface BatchCheckResult {
  allowed: boolean;
}

interface KetoBatchResponse {
  results?: BatchCheckResult[];
}

interface AuthResponse {
  authorized: boolean;
  results: BatchCheckResult[];
}

interface ErrorResponse {
  error: string;
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString();
}

function sendJson(res: ServerResponse, statusCode: number, data: AuthResponse | ErrorResponse | { status: string }): void {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

export async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.url === '/health') {
    sendJson(res, 200, { status: 'ok' });
    return;
  }

  if (req.method !== 'POST') {
    sendJson(res, 405, { error: 'Method not allowed' });
    return;
  }

  try {
    const body = await readBody(req);
    const requestData: unknown = JSON.parse(body);

    const ketoResponse = await fetch(`${config.ketoReadUrl}/relation-tuples/batch/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestData),
    });

    const ketoData = await ketoResponse.json() as KetoBatchResponse;
    const results = ketoData.results || [];
    const hasAllowed = results.some((result) => result.allowed === true);

    if (hasAllowed) {
      sendJson(res, 200, { authorized: true, results });
    } else {
      sendJson(res, 403, { authorized: false, results });
    }
  } catch (error) {
    console.error('Proxy error:', error);
    sendJson(res, 500, { error: 'Internal server error' });
  }
}
