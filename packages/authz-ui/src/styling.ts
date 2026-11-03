/**
 * The named parts of the components' markup. Inside an element's shadow root
 * a host restyles each with `::part(name)`; an element can carry several, so
 * `::part(button primary)` reaches only primary buttons.
 */
export const Part = {
  toolbar: 'toolbar',
  heading: 'heading',
  list: 'list',
  table: 'table',
  row: 'row',
  cell: 'cell',
  form: 'form',
  field: 'field',
  label: 'label',
  input: 'input',
  grant: 'grant',
  scope: 'scope',
  actions: 'actions',
  button: 'button',
  primary: 'primary',
  danger: 'danger',
  verdict: 'verdict',
  problems: 'problems',
  failure: 'failure',
  loading: 'loading',
  empty: 'empty',
  pager: 'pager',
} as const;
export type Part = (typeof Part)[keyof typeof Part];

export const parts = (...names: Array<Part | false | undefined>): string => names.filter(Boolean).join(' ');

/**
 * The theme a host sets, on the element or any ancestor, the page's root
 * included. Each one left unset falls back to the stylesheet's own value.
 */
export const CssVar = {
  font: '--iam-font',
  mono: '--iam-mono',
  text: '--iam-text',
  muted: '--iam-muted',
  surface: '--iam-surface',
  border: '--iam-border',
  radius: '--iam-radius',
  gap: '--iam-gap',
  accent: '--iam-accent',
  accentText: '--iam-accent-text',
  danger: '--iam-danger',
  accepted: '--iam-accepted',
  refused: '--iam-refused',
  waiting: '--iam-waiting',
} as const;
export type CssVar = (typeof CssVar)[keyof typeof CssVar];
