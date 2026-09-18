// Self-scheduling bounded reconciler for the trending list.
//
// The visible trending list is fed by pushed `market:trending` frames; this
// poller is the reconciliation fallback that keeps ranks/identity fresh even
// when the realtime lane is unavailable. It is deliberately conservative:
//
// - **no overlap**: the next timer is armed only after the previous refresh
//   settles, so a slow command can never stack requests;
// - **defer when hidden**: a background tab performs no refresh and re-checks
//   at a bounded interval, then resumes immediately when it becomes visible;
// - **back off when degraded**: an offline/reconnecting connection slows the
//   cadence with exponential backoff up to a hard cap.
//
// Timers/visibility are injectable so the cadence is unit-testable with fake
// timers and no real waiting.

export type PollerTimerHandle = ReturnType<typeof setTimeout>;

export interface TrendingPollerOptions {
  /** One reconciliation attempt. May be sync or async. */
  readonly refresh: () => void | Promise<void>;
  /** False while the encrypted command channel is not usable. */
  readonly isReady: () => boolean;
  /** True while the document/tab is hidden. */
  readonly isHidden: () => boolean;
  /** True while the realtime connection is degraded/offline. */
  readonly isDegraded: () => boolean;
  /** Active-tab cadence (production target 2s). */
  readonly intervalMs?: number;
  /** Deferred cadence while hidden. */
  readonly hiddenIntervalMs?: number;
  /** First backoff step while degraded. */
  readonly degradedIntervalMs?: number;
  /** Backoff ceiling. */
  readonly maxBackoffMs?: number;
  readonly setTimer?: (fn: () => void, ms: number) => PollerTimerHandle;
  readonly clearTimer?: (handle: PollerTimerHandle) => void;
  /** Subscribe to visibility changes; returns an unsubscribe fn. */
  readonly subscribeVisibility?: (cb: () => void) => () => void;
}

export interface TrendingPoller {
  /** Arm the loop. Safe to call again after {@link stop}. */
  start(): void;
  /** Pause the loop without releasing the visibility subscription. */
  stop(): void;
  /** Run the next attempt immediately (used when the tab becomes visible). */
  kick(): void;
  /** Terminal teardown: stop and release the visibility subscription. */
  dispose(): void;
  readonly running: boolean;
}

export const TRENDING_INTERVAL_MS = 2_000;
export const TRENDING_HIDDEN_INTERVAL_MS = 15_000;
export const TRENDING_DEGRADED_INTERVAL_MS = 5_000;
export const TRENDING_MAX_BACKOFF_MS = 30_000;

export function createTrendingPoller(options: TrendingPollerOptions): TrendingPoller {
  const intervalMs = options.intervalMs ?? TRENDING_INTERVAL_MS;
  const hiddenIntervalMs = options.hiddenIntervalMs ?? TRENDING_HIDDEN_INTERVAL_MS;
  const degradedIntervalMs = options.degradedIntervalMs ?? TRENDING_DEGRADED_INTERVAL_MS;
  const maxBackoffMs = options.maxBackoffMs ?? TRENDING_MAX_BACKOFF_MS;
  const setTimer = options.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
  const clearTimer = options.clearTimer ?? ((handle) => clearTimeout(handle));

  let running = false;
  let handle: PollerTimerHandle | undefined;
  let backoff = 0;
  let disposed = false;
  // An async refresh may still be settling when a kick arrives (e.g. the tab
  // became visible). Coalesce it into one deferred tick instead of starting a
  // concurrent refresh.
  let inFlight = false;
  let kickPending = false;

  const clear = (): void => {
    if (handle !== undefined) {
      clearTimer(handle);
      handle = undefined;
    }
  };

  const schedule = (delay: number): void => {
    if (!running || disposed) return;
    clear();
    handle = setTimer(() => {
      handle = undefined;
      void run();
    }, delay);
  };

  const kick = (): void => {
    if (!running || disposed) return;
    if (inFlight) {
      kickPending = true;
      return;
    }
    schedule(0);
  };

  const run = async (): Promise<void> => {
    if (!running || disposed) return;
    if (options.isHidden()) {
      backoff = 0;
      schedule(hiddenIntervalMs);
      return;
    }
    if (!options.isReady()) {
      backoff = 0;
      schedule(degradedIntervalMs);
      return;
    }
    const degraded = options.isDegraded();
    if (degraded) {
      backoff = backoff === 0 ? degradedIntervalMs : Math.min(backoff * 2, maxBackoffMs);
    } else {
      backoff = 0;
    }
    inFlight = true;
    try {
      const result = options.refresh();
      if (result && typeof (result as Promise<void>).then === "function") {
        await result;
      }
    } catch {
      // A failed reconciliation is retried on the next bounded tick; it must
      // never break the loop or surface as an unhandled rejection.
    } finally {
      inFlight = false;
    }
    if (!running || disposed) return;
    if (kickPending) {
      // A kick arrived while this refresh was settling: honour it now with a
      // single immediate tick, still after the previous refresh completed.
      kickPending = false;
      schedule(0);
      return;
    }
    schedule(degraded ? backoff : intervalMs);
  };

  const unsubscribeVisibility = options.subscribeVisibility?.(() => {
    // Becoming visible resumes immediately; becoming hidden lets the next tick
    // observe `isHidden` and defer (the deferred tick performs no refresh).
    if (!options.isHidden()) kick();
  });

  const stop = (): void => {
    running = false;
    backoff = 0;
    kickPending = false;
    inFlight = false;
    clear();
  };

  return {
    get running() {
      return running;
    },
    start(): void {
      if (running || disposed) return;
      running = true;
      // The caller performs the first read when it becomes ready; the poller
      // arms its first bounded tick one interval out.
      schedule(intervalMs);
    },
    stop,
    dispose(): void {
      if (disposed) return;
      stop();
      disposed = true;
      unsubscribeVisibility?.();
    },
    kick,
  };
}
