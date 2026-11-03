import env from 'env-var';

import type { Timing } from './leader';

export const config = {
  port: env.get('PORT').default('3003').asPortNumber(),
  ketoWriteUrl: env.get('KETO_WRITE_URL').default('http://keto-write.ory.svc.cluster.local').asString(),
  ketoReadUrl: env.get('KETO_READ_URL').default('http://keto-read.ory.svc.cluster.local').asString(),
};

/** Who this replica is in an election, and where the leader takes the writes it alone makes. */
export const replica = (): { identity: string; address: string } => ({
  identity: env.get('POD_NAME').required().asString(),
  address: `http://${env.get('POD_IP').required().asString()}:${config.port}`,
});

/** How a lease is held, which the deployment sets from the API server's measured write latency. */
export const leaseTiming = (): Timing => ({
  durationSeconds: env.get('LEASE_DURATION_SECONDS').required().asIntPositive(),
  renewDeadlineMs: env.get('LEASE_RENEW_DEADLINE_MS').required().asIntPositive(),
  renewEveryMs: env.get('LEASE_RENEW_EVERY_MS').required().asIntPositive(),
});
