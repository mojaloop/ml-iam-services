import { createGuard } from '@mojaloop/authz';
import { StatusCodes } from 'http-status-codes';
import { K8s, kind } from 'kubernetes-fluent-client';

import { ALL_INTERFACES } from '../http/address';
import { closeOnSignals } from '../http/backend';
import { KetoReads } from '../iam/keto';
import { AuthzRole } from '../operator/cluster';
import { config } from './config';
import { Document, documentAt } from './documents';
import { Identities } from './identities';
import { ApiState, controllerAt, Feed, internalApi, publicApi, refusedBy, RoleStore } from './server';
import { ANNOUNCED_ETAG } from './vocabulary';

export interface StartOptions {
  /** The controller's API, which takes every assignment and serves the composition. */
  controllerUrl?: string;
  /** Where roles composed here are written, which is the controller's own namespace. */
  namespace?: string;
  /** The ConfigMap the controller announces the composition's ETag in. */
  announcedIn?: string;
  kratosAdminUrl?: string;
  kratosPublicUrl?: string;
  hydraAdminUrl?: string;
}

const required = (value: string | undefined, flag: string): string => {
  if (value === undefined || value === '') throw new Error(`${flag} is required`);
  return value;
};

/** The roles composed here, as objects in the IAM's namespace. */
export const clusterRoles = (namespace: string): RoleStore => ({
  get: async (name) => {
    try {
      return await K8s(AuthzRole).InNamespace(namespace).Get(name);
    } catch (error) {
      if (refusedBy(error)?.status === StatusCodes.NOT_FOUND) return undefined;
      throw error;
    }
  },
  create: async (role) => {
    await K8s(AuthzRole).Create(role);
  },
  apply: async (role) => {
    await K8s(AuthzRole).Apply(role, { force: true });
  },
  delete: async (name) => {
    await K8s(AuthzRole).InNamespace(namespace).Delete(name);
  },
});

export async function start(options: StartOptions): Promise<void> {
  const namespace = required(options.namespace, '--namespace');
  const controllerUrl = required(options.controllerUrl, '--controller-url');
  const announcedIn = required(options.announcedIn, '--announced-in');
  const feed = new Feed(controllerUrl);
  const state: ApiState = {
    namespace,
    keto: new KetoReads(config.ketoReadUrl),
    composition: feed,
    identities: new Identities({
      kratosAdmin: required(options.kratosAdminUrl, '--kratos-admin-url'),
      kratosPublic: required(options.kratosPublicUrl, '--kratos-public-url'),
      hydraAdmin: required(options.hydraAdminUrl, '--hydra-admin-url'),
    }),
    roles: clusterRoles(namespace),
    controller: controllerAt(controllerUrl),
  };

  const announcement = K8s(kind.ConfigMap, { namespace, name: announcedIn }).Watch((configMap) => {
    feed.wanted = configMap.data?.[ANNOUNCED_ETAG];
    if (feed.behind) feed.readSoon();
  });
  await announcement.start();
  feed.readSoon();

  const publicServer = await publicApi(state, await createGuard(documentAt(Document.public)));
  const internalServer = await internalApi(state);
  await publicServer.listen({ port: config.publicPort, host: ALL_INTERFACES });
  await internalServer.listen({ port: config.internalPort, host: ALL_INTERFACES });
  console.log(`IAM api listening: public on ${config.publicPort}, internal on ${config.internalPort}`);

  closeOnSignals([publicServer, internalServer], () => announcement.close());
}
