import { GenericKind, K8s, kind,RegisterKind, WatchCfg } from 'kubernetes-fluent-client';
import { WatchPhase } from 'kubernetes-fluent-client/dist/fluent/shared-types';

import { AuthzDocumentResource } from './sources';

/**
 * The cluster side of reconciling: what a service declares while the
 * deployment runs, and where the result is published.
 *
 * Who may declare what is Kubernetes' answer: a service's ServiceAccount is
 * granted write on its own AuthzDocument by name, and the API server enforces
 * it.
 */

/** The custom resource a service's own operator writes when its surface changes. */
export class AuthzDocument extends GenericKind {
  declare spec?: {
    document?: string;
    url?: { host?: string; path?: string };
  };
  declare status?: {
    /** `Accepted`, `Refused` or `Blocked`, so `kubectl get` tells the story. */
    state?: string;
    /** The service this document declares. */
    service?: string;
    /** What refused it, in the words the composer used. */
    messages?: string[];
    /** The generation this status answers, so a stale status is visible. */
    observedGeneration?: number;
  };
}

RegisterKind(AuthzDocument, {
  group: 'mojaloop.io',
  version: 'v1',
  kind: 'AuthzDocument',
  plural: 'authzdocuments',
});

/** Every document declared in the cluster right now. */
export const listDocuments = async (namespace: string): Promise<AuthzDocumentResource[]> => {
  const list = await K8s(AuthzDocument).InNamespace(namespace).Get();
  return list.items as AuthzDocumentResource[];
};

/**
 * Calls back whenever a document appears, changes or leaves. The client keeps
 * the connection and the resource version, so a reconnect resumes where it
 * left off, and a resync catches what changed while it was gone.
 */
export const watchDocuments = async (
  namespace: string,
  onChange: (name: string, phase: WatchPhase) => Promise<void>,
  cfg: WatchCfg = {},
): Promise<{ close: () => void }> => {
  const watcher = K8s(AuthzDocument)
    .InNamespace(namespace)
    .Watch(async (doc, phase) => {
      await onChange(doc.metadata?.name ?? '(unnamed)', phase);
    }, cfg);

  await watcher.start();
  return { close: () => watcher.close() };
};

/**
 * Tells a document's author what became of it. An operator that generated a
 * document reads its own resource to find out whether the platform took it.
 */
export const reportOn = async (
  namespace: string,
  name: string,
  status: { state: string; service?: string; messages: string[]; observedGeneration?: number },
): Promise<void> => {
  await K8s(AuthzDocument, { namespace, name }).PatchStatus({
    metadata: { name, namespace },
    status,
  } as AuthzDocument);
};

/**
 * Publishes what a reconcile produced, as the files the gateway and Keto boot
 * from. Server-side apply, so the object converges on what this process says.
 */
export const publish = async (
  namespace: string,
  name: string,
  data: Record<string, string>,
): Promise<void> => {
  await K8s(kind.ConfigMap).Apply(
    {
      metadata: {
        name,
        namespace,
        labels: { 'app.kubernetes.io/managed-by': 'ml-iam-services' },
      },
      data,
    },
    { force: true },
  );
};
