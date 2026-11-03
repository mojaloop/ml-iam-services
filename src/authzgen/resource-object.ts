/**
 * The object Keto holds a resource on: its resource name and its id, the
 * gateway's checks and the IAM's grants alike. No resource name holds the
 * separator.
 */

const SEPARATOR = '/';

export interface ResourceInstance {
  resourceName: string;
  id: string;
}

export const resourceObject = (resourceName: string, id: string): string => `${resourceName}${SEPARATOR}${id}`;

/** An object Keto holds, read back into the resource it stands for, or nothing for one that is no resource. */
export const parseResource = (object: string): ResourceInstance | undefined => {
  const at = object.indexOf(SEPARATOR);
  return at > 0 ? { resourceName: object.slice(0, at), id: object.slice(at + SEPARATOR.length) } : undefined;
};
