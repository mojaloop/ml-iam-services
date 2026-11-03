import type { components } from './generated/public';

export type Localized = components['schemas']['Localized'];

/**
 * The text for one language. A per-language map without that language answers
 * its first entry, so a role written in one language still reads in another.
 */
export function localize(text: Localized | undefined, language?: string): string | undefined {
  if (text === undefined || typeof text === 'string') return text;
  if (language !== undefined && text[language] !== undefined) return text[language];
  return Object.values(text)[0];
}
