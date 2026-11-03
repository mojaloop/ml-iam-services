import { useQueryClient } from '@tanstack/react-query';
import { createContext, type ReactNode, useContext, useMemo } from 'react';

import type { AuthzClient } from '../client';
import { composed } from './keys';
import { english, type Messages } from './messages';

interface LiveComposition {
  /** Opens the change stream for the first holder, closes it when the last lets go. */
  hold(): () => void;
}

interface AuthzContextValue {
  client: AuthzClient;
  language?: string;
  messages: Messages;
  live: LiveComposition;
}

const AuthzContext = createContext<AuthzContextValue | undefined>(undefined);

export interface AuthzProviderProps {
  client: AuthzClient;
  /** The language display text is shown in; text without it shows its first entry. */
  language?: string;
  messages?: Partial<Messages>;
  children?: ReactNode;
}

/** Gives the hooks and components their client. It sits inside the app's `QueryClientProvider`. */
export function AuthzProvider({ client, language, messages, children }: AuthzProviderProps) {
  const queries = useQueryClient();
  const live = useMemo((): LiveComposition => {
    let holders = 0;
    let close: (() => void) | undefined;
    const reread = () => {
      for (const queryKey of composed) void queries.invalidateQueries({ queryKey });
    };
    return {
      hold() {
        holders += 1;
        if (holders === 1) close = client.watchChanges({ onChange: reread });
        return () => {
          holders -= 1;
          if (holders === 0) {
            close?.();
            close = undefined;
          }
        };
      },
    };
  }, [client, queries]);
  const value = useMemo(
    () => ({ client, language, messages: { ...english, ...messages }, live }),
    [client, language, messages, live],
  );
  return <AuthzContext value={value}>{children}</AuthzContext>;
}

export function useAuthz(): AuthzContextValue {
  const value = useContext(AuthzContext);
  if (value === undefined) throw new Error('an authz-ui hook or component is used outside <AuthzProvider>');
  return value;
}

/** The language a component shows text in: its own prop, else the provider's. */
export function useLanguage(language?: string): string | undefined {
  const { language: provided } = useAuthz();
  return language ?? provided;
}
