/**
 * The words the platform reserves. Every one starts with `$`, which no
 * resource id and no resource type may, so a reserved word is never read as
 * one of them.
 */

import { Separator } from '~/format';

export const RESERVED = '$';

/** Every resource of a type, present and future. */
export const ALL: `${typeof RESERVED}all` = `${RESERVED}all`;

/** In a `scopedBy`: every resource name the deployment declares, each under its own name. */
export const RESOURCES: `${typeof RESERVED}resources` = `${RESERVED}resources`;

/**
 * Why a string cannot be a resource id, or nothing when it can: it would be
 * read as a reserved word, or split apart in the scope a service is handed.
 */
export const idProblem = (id: string): string | undefined => {
  if (id === '') return 'a resource id is not empty';
  if (id.startsWith(RESERVED)) return `${id} starts with ${RESERVED}, which only reserved words do`;
  const splits = [Separator.ids, Separator.types].filter((separator) => id.includes(separator));
  if (splits.length > 0) return `${id} holds ${splits.join(' and ')}, which separate ids in the scope a service is handed`;
  return undefined;
};
