import { join } from 'node:path';

/** The IAM's own API documents, which ship beside the code that serves them. */
export const Document = { public: 'public.yaml', internal: 'internal.yaml', controller: 'controller.yaml' } as const;
export type Document = (typeof Document)[keyof typeof Document];

export const documentAt = (name: Document): string => join(__dirname, name);
