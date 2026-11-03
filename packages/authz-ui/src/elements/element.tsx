import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';

import { type AuthzClient, createAuthzClient } from '../client';
import componentStyles from '../default.css?inline';
import { AuthzProvider } from '../react/context';
import type { Messages } from '../react/messages';
import elementStyles from './element.css?inline';
import { Attribute, type IamEventMap } from './names';

export type Fetch = (request: Request) => Promise<Response>;

/** What a component calls to dispatch one of its element's events; `false` when a listener cancelled it. */
export type Emit = <K extends keyof IamEventMap>(
  type: K,
  detail: IamEventMap[K]['detail'],
  cancelable?: boolean,
) => boolean;

const OFF = 'false';

interface Connection {
  generation: number;
  apiBase: string;
  fetch: Fetch | undefined;
  eventSource: typeof EventSource | undefined;
  client: AuthzClient;
  queries: QueryClient;
}

/**
 * One of the IAM's components as a custom element: rendered in its own shadow
 * root with its stylesheet, talking to the IAM's public API at `apiBase`
 * through the host's `fetch` when it gives one.
 */
export abstract class IamElement extends HTMLElement {
  static readonly observedAttributes: readonly string[] = [Attribute.apiBase, Attribute.language];

  #container: HTMLElement;
  #root: Root | undefined;
  #scheduled = false;
  #connection: Connection | undefined;
  #fetch: Fetch | undefined;
  #eventSource: typeof EventSource | undefined;
  #messages: Partial<Messages> | undefined;

  constructor() {
    super();
    const shadow = this.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = `${componentStyles}\n${elementStyles}`;
    this.#container = document.createElement('div');
    this.#container.className = 'authz-element';
    shadow.append(style, this.#container);
  }

  /** Where the gateway serves the IAM's public API, absolute or relative to the page. Nothing renders until it is set. */
  get apiBase(): string {
    return this.getAttribute(Attribute.apiBase) ?? '';
  }

  set apiBase(value: string) {
    this.setAttribute(Attribute.apiBase, value);
  }

  /** The language display text is shown in. */
  get language(): string | undefined {
    return this.getAttribute(Attribute.language) ?? undefined;
  }

  set language(value: string | undefined) {
    this.setText(Attribute.language, value);
  }

  /** Sends every request to the IAM, so the host adds its own authentication and headers; the browser's when absent. */
  get fetch(): Fetch | undefined {
    return this.#fetch;
  }

  set fetch(value: Fetch | undefined) {
    this.#fetch = value;
    this.update();
  }

  /** Opens the IAM's change stream; the browser's own when absent. */
  get eventSource(): typeof EventSource | undefined {
    return this.#eventSource;
  }

  set eventSource(value: typeof EventSource | undefined) {
    this.#eventSource = value;
    this.update();
  }

  /** The components' own words, replacing the English ones they name. */
  get messages(): Partial<Messages> | undefined {
    return this.#messages;
  }

  set messages(value: Partial<Messages> | undefined) {
    this.#messages = value;
    this.update();
  }

  connectedCallback(): void {
    this.#adoptEarlyProperties();
    this.update();
  }

  disconnectedCallback(): void {
    queueMicrotask(() => {
      if (this.isConnected || this.#root === undefined) return;
      this.#root.unmount();
      this.#root = undefined;
    });
  }

  attributeChangedCallback(_name: string, previous: string | null, value: string | null): void {
    if (previous !== value) this.update();
  }

  /** The element's React tree; typed loosely so the element's declarations need no React. */
  protected abstract view(): unknown;

  protected readonly emit: Emit = (type, detail, cancelable = false) =>
    this.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true, cancelable }));

  protected flag(attribute: Attribute, fallback: boolean): boolean {
    const value = this.getAttribute(attribute);
    return value === null ? fallback : value !== OFF;
  }

  protected setFlag(attribute: Attribute, value: boolean): void {
    this.setAttribute(attribute, value ? '' : OFF);
  }

  protected setText(attribute: Attribute, value: string | undefined): void {
    if (value === undefined) this.removeAttribute(attribute);
    else this.setAttribute(attribute, value);
  }

  protected update(): void {
    if (this.#scheduled) return;
    this.#scheduled = true;
    queueMicrotask(() => {
      this.#scheduled = false;
      this.#render();
    });
  }

  /**
   * A property a host set before the element was defined is an own property
   * shadowing the class's accessor; it is moved onto the accessor.
   */
  #adoptEarlyProperties(): void {
    const prototype = Object.getPrototypeOf(this) as object;
    for (const key of Object.keys(this)) {
      if (!(key in prototype)) continue;
      const value: unknown = Reflect.get(this, key);
      Reflect.deleteProperty(this, key);
      Reflect.set(this, key, value);
    }
  }

  #connect(): Connection | undefined {
    const apiBase = this.apiBase;
    if (apiBase === '') return undefined;
    const made = this.#connection;
    if (made?.apiBase === apiBase && made.fetch === this.#fetch && made.eventSource === this.#eventSource) return made;
    this.#connection = {
      generation: (made?.generation ?? 0) + 1,
      apiBase,
      fetch: this.#fetch,
      eventSource: this.#eventSource,
      client: createAuthzClient({ baseUrl: apiBase, fetch: this.#fetch, EventSource: this.#eventSource }),
      queries: new QueryClient({ defaultOptions: { queries: { retry: false } } }),
    };
    return this.#connection;
  }

  #render(): void {
    if (!this.isConnected) return;
    const connection = this.#connect();
    this.#root ??= createRoot(this.#container);
    this.#root.render(
      connection === undefined ? null : (
        <QueryClientProvider key={connection.generation} client={connection.queries}>
          <AuthzProvider client={connection.client} language={this.language} messages={this.#messages}>
            {this.view() as ReactNode}
          </AuthzProvider>
        </QueryClientProvider>
      ),
    );
  }
}
