/**
 * The Ready condition every deployment object carries, in Kubernetes's own
 * shape so Flux's health checks and `kubectl wait --for=condition=Ready` read
 * it.
 */

export interface Condition {
  type: string;
  status: 'True' | 'False' | 'Unknown';
  reason: string;
  message?: string;
  observedGeneration?: number;
  lastTransitionTime: string;
}

export type Reason = 'Accepted' | 'Refused' | 'Waiting';

export interface Verdict {
  reason: Reason;
  message: string;
}

/** A transition time moves only when the status does, so an unchanged verdict writes nothing new. */
export const readyCondition = (
  previous: Condition[] | undefined,
  verdict: Verdict,
  generation: number | undefined,
  now: string = new Date().toISOString(),
): Condition => {
  const status = verdict.reason === 'Accepted' ? 'True' : 'False';
  const before = previous?.find((c) => c.type === 'Ready');
  return {
    type: 'Ready',
    status,
    reason: verdict.reason,
    message: verdict.message,
    ...(generation !== undefined ? { observedGeneration: generation } : {}),
    lastTransitionTime: before !== undefined && before.status === status ? before.lastTransitionTime : now,
  };
};
