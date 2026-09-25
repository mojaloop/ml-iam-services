/**
 * A permission prefix is the deployment's word, written on a route, and a
 * Keto namespace is a class in the Ory Permission Language, which only takes
 * an identifier. The namespace is the prefix itself when that is already an
 * identifier, so a stored tuple never moves; otherwise every other character
 * is written as `_<hex code>_`. Two prefixes meeting on one namespace is
 * refused where services are composed.
 */

/** Letters, digits, `_` and `-`, starting with a letter or digit: never a `.`, which ends a prefix in a permission id. */
export const PREFIX = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

export const ketoNamespace = (prefix: string): string => {
  if (IDENTIFIER.test(prefix)) return prefix;
  const encoded = [...prefix]
    .map((c) => (/[A-Za-z0-9_]/.test(c) ? c : `_${c.codePointAt(0)!.toString(16)}_`))
    .join('');
  return /^[0-9]/.test(encoded) ? `_${encoded}` : encoded;
};
