/**
 * A permission id: the prefix the route gives a service, then the
 * operationId. A prefix holds no `.`, so the first one separates the two.
 */

const SEPARATOR = '.';

export const permissionId = (service: string, operationId: string): string => `${service}${SEPARATOR}${operationId}`;

/** The service a permission belongs to. */
export const serviceOf = (id: string): string => {
  const at = id.indexOf(SEPARATOR);
  return at < 0 ? id : id.slice(0, at);
};
