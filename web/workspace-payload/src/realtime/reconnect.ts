export interface BackoffPolicy {
  readonly baseMs: number;
  readonly maxMs: number;
  readonly factor: number;
  /** 0..1 fraction of jitter applied around the exponential delay. */
  readonly jitter: number;
}

export const DEFAULT_BACKOFF: BackoffPolicy = {
  baseMs: 500,
  maxMs: 30_000,
  factor: 1.8,
  jitter: 0.5,
};

/**
 * Equal-jitter exponential backoff. `random` is injected so tests are
 * deterministic. Attempt is 0-based (first retry = attempt 0).
 */
export function backoffDelay(
  attempt: number,
  policy: BackoffPolicy = DEFAULT_BACKOFF,
  random: () => number = Math.random,
): number {
  const safeAttempt = Math.max(0, Math.min(attempt, 32));
  let raw = policy.baseMs;
  for (let i = 0; i < safeAttempt; i++) {
    raw *= policy.factor;
    if (raw >= policy.maxMs) {
      raw = policy.maxMs;
      break;
    }
  }
  raw = Math.min(raw, policy.maxMs);
  const jitter = Math.max(0, Math.min(1, policy.jitter));
  const lower = raw * (1 - jitter);
  const spread = raw - lower;
  const value = lower + random() * spread;
  return Math.max(0, Math.min(policy.maxMs, Math.round(value)));
}
