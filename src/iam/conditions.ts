/**
 * The Ready condition every deployment object carries, in Kubernetes's own
 * shape so Flux's health checks and `kubectl wait --for=condition=Ready` read
 * it.
 */

const READY = 'Ready';

export const Status = { true: 'True', false: 'False', unknown: 'Unknown' } as const;
export type Status = (typeof Status)[keyof typeof Status];

export interface Condition {
  type: string;
  status: Status;
  reason: string;
  message?: string;
  observedGeneration?: number;
  lastTransitionTime: string;
}

export const Reason = { accepted: 'Accepted', refused: 'Refused', waiting: 'Waiting' } as const;
export type Reason = (typeof Reason)[keyof typeof Reason];

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
  const status = verdict.reason === Reason.accepted ? Status.true : Status.false;
  const before = previous?.find((c) => c.type === READY);
  return {
    type: READY,
    status,
    reason: verdict.reason,
    message: verdict.message,
    ...(generation !== undefined ? { observedGeneration: generation } : {}),
    lastTransitionTime: before !== undefined && before.status === status ? before.lastTransitionTime : now,
  };
};
