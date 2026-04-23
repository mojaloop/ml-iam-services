import { IncomingMessage, ServerResponse } from 'node:http';

import { config } from './config';

interface RelationTuple {
  object: string;
}

interface KetoResponse {
  relation_tuples?: RelationTuple[];
}

interface KratosIdentity {
  schema_id: string;
  state: string;
  traits: Record<string, unknown>;
}

interface InjectRolesRequest {
  identity_id: string;
  user_subject: string;
}

interface SuccessResponse {
  success: boolean;
  roles: string[];
}

interface ErrorResponse {
  error: string;
}

interface HealthResponse {
  status: string;
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString();
}

function sendJson(res: ServerResponse, statusCode: number, data: SuccessResponse | ErrorResponse | HealthResponse): void {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

export async function getUserRoles(userSubject: string): Promise<string[]> {
  try {
    const response = await fetch(
      `${config.ketoReadUrl}/relation-tuples?subject_id=${userSubject}&namespace=role&relation=member`
    );
    if (!response.ok) return ['everyone'];

    const data = await response.json() as KetoResponse;
    const relationTuples = data.relation_tuples || [];
    const roles = relationTuples.map((t) => t.object);

    return [...new Set([...roles, 'everyone'])];
  } catch {
    return ['everyone'];
  }
}

export async function updateIdentityRoles(
  identityId: string,
  userSubject: string
): Promise<SuccessResponse | ErrorResponse> {
  try {
    const [roles, identityResponse] = await Promise.all([
      getUserRoles(userSubject),
      fetch(`${config.kratosAdminUrl}/admin/identities/${identityId}`),
    ]);

    const identity = await identityResponse.json() as KratosIdentity;

    console.log(`User ${userSubject} roles:`, roles);

    const updateBody = {
      schema_id: identity.schema_id,
      state: identity.state,
      traits: { ...identity.traits, roles },
    };

    const response = await fetch(`${config.kratosAdminUrl}/admin/identities/${identityId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updateBody),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Kratos update failed: ${response.status} - ${errorText}`);
      return { error: `Update failed: ${response.status}` };
    }

    return { success: true, roles };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return { error: message };
  }
}

export async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'GET' && req.url === '/health') {
    sendJson(res, 200, { status: 'healthy' });
    return;
  }

  if (req.method === 'POST' && req.url === '/inject-roles') {
    try {
      const body = await readBody(req);
      const { identity_id, user_subject } = JSON.parse(body) as InjectRolesRequest;

      if (!identity_id || !user_subject) {
        sendJson(res, 400, { error: 'Missing required fields' });
        return;
      }

      console.log(`Processing: ${user_subject}`);
      const result = await updateIdentityRoles(identity_id, user_subject);

      if ('error' in result) {
        sendJson(res, 500, result);
      } else {
        sendJson(res, 200, result);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      sendJson(res, 500, { error: message });
    }
    return;
  }

  sendJson(res, 404, { error: 'Not found' });
}
