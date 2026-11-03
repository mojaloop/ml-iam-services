/** A namespaced Kubernetes object. */
export interface ObjectRef {
  namespace: string;
  name: string;
}

/** Where Kubernetes puts an object whose manifest names no namespace. */
export const DEFAULT_NAMESPACE = 'default';

/** What a message calls an object read without a name. */
const UNNAMED = '(unnamed)';

export const refOf = (metadata?: { namespace?: string; name?: string }): ObjectRef => ({
  namespace: metadata?.namespace ?? DEFAULT_NAMESPACE,
  name: metadata?.name ?? UNNAMED,
});

export const sameObject = (a: ObjectRef, b: ObjectRef): boolean => a.namespace === b.namespace && a.name === b.name;

/** `<namespace>/<name>`, for a message. */
export const describeObject = (ref: ObjectRef): string => `${ref.namespace}/${ref.name}`;

/**
 * Something wrong with what the deployment declared, with every object it
 * concerns, so each one is told it without reading the message.
 */
export interface Problem {
  message: string;
  routes?: ObjectRef[];
  documents?: ObjectRef[];
  services?: string[];
  resourceNames?: string[];
}

export const concernsObject = (refs: ObjectRef[] | undefined, ref: ObjectRef): boolean =>
  refs?.some((r) => sameObject(r, ref)) ?? false;

export const messagesOf = (problems: Problem[]): string[] => problems.map((p) => p.message);
