import env from 'env-var';

export const config = {
  publicPort: env.get('PUBLIC_PORT').default('3004').asPortNumber(),
  internalPort: env.get('INTERNAL_PORT').default('3005').asPortNumber(),
  ketoReadUrl: env.get('KETO_READ_URL').default('http://keto-read.ory.svc.cluster.local').asString(),
};
