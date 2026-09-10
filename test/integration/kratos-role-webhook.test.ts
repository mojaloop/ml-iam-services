const KETO_WRITE_URL = process.env.KETO_WRITE_URL || 'http://localhost:4467';
const KRATOS_ADMIN_URL = process.env.KRATOS_ADMIN_URL || 'http://localhost:4434';
const WEBHOOK_URL = process.env.KRATOS_ROLE_WEBHOOK_URL || 'http://localhost:8080';

interface Identity {
  id: string;
  traits: {
    email: string;
  };
  metadata_public?: {
    roles?: string[];
  };
}

interface HealthResponse {
  status: string;
}

interface InjectRolesResponse {
  success: boolean;
  roles: string[];
}

interface ErrorResponse {
  error: string;
}

describe('kratos-role-webhook integration', () => {
  let identityId: string;
  const userSubject = 'test-user-' + Date.now();

  beforeAll(async () => {
    const identityResponse = await fetch(`${KRATOS_ADMIN_URL}/admin/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        schema_id: 'default',
        traits: {
          email: `${userSubject}@test.com`,
        },
      }),
    });
    const identity = await identityResponse.json() as Identity;
    identityId = identity.id;

    await fetch(`${KETO_WRITE_URL}/admin/relation-tuples`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        namespace: 'Role',
        object: 'admin',
        relation: 'members',
        subject_id: userSubject,
      }),
    });

    await fetch(`${KETO_WRITE_URL}/admin/relation-tuples`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        namespace: 'Role',
        object: 'user',
        relation: 'members',
        subject_id: userSubject,
      }),
    });
  });

  afterAll(async () => {
    if (identityId) {
      await fetch(`${KRATOS_ADMIN_URL}/admin/identities/${identityId}`, {
        method: 'DELETE',
      });
    }

    await fetch(`${KETO_WRITE_URL}/admin/relation-tuples?namespace=Role&object=admin&relation=members&subject_id=${userSubject}`, {
      method: 'DELETE',
    });
    await fetch(`${KETO_WRITE_URL}/admin/relation-tuples?namespace=Role&object=user&relation=members&subject_id=${userSubject}`, {
      method: 'DELETE',
    });
  });

  describe('health check', () => {
    it('should return healthy', async () => {
      const response = await fetch(`${WEBHOOK_URL}/health`);
      expect(response.status).toBe(200);
      const data = await response.json() as HealthResponse;
      expect(data.status).toBe('healthy');
    });
  });

  describe('inject-roles', () => {
    it('should inject roles into identity', async () => {
      const response = await fetch(`${WEBHOOK_URL}/inject-roles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity_id: identityId,
          user_subject: userSubject,
        }),
      });

      expect(response.status).toBe(200);
      const data = await response.json() as InjectRolesResponse;
      expect(data.success).toBe(true);
      expect(data.roles).toContain('admin');
      expect(data.roles).toContain('user');
      expect(data.roles).toContain('everyone');

      const identityResponse = await fetch(`${KRATOS_ADMIN_URL}/admin/identities/${identityId}`);
      const identity = await identityResponse.json() as Identity;
      expect(identity.metadata_public?.roles).toContain('admin');
      expect(identity.metadata_public?.roles).toContain('user');
      expect(identity.metadata_public?.roles).toContain('everyone');
    });

    it('should return error for missing fields', async () => {
      const response = await fetch(`${WEBHOOK_URL}/inject-roles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
      const data = await response.json() as ErrorResponse;
      expect(data.error).toBe('Missing required fields');
    });
  });
});

export {};
