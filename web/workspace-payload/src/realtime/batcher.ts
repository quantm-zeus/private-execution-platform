import type { DecodedFrame, Priority } from "./types";

export interface FrameBatcherOptions {
  /** Total frames retained across all priorities before eviction starts. */
  readonly capacity: number;
  /** Per-priority flush interval in ms. P0 should be 0 (immediate). */
  readonly flushMs: Record<Priority, number>;
}

export const DEFAULT_FLUSH_MS: Record<Priority, number> = {
  0: 0,
  1: 60,
  2: 400,
  3: 1_000,
};

export interface EnqueueResult {
  /** A newer frame replaced an older one with the same coalescing key. */
  readonly replaced: boolean;
  /** A bounded-buffer eviction happened; the caller must force a resync. */
  readonly forcedResync: boolean;
}

/**
 * Bounded, coalescing, priority-aware frame buffer.
 *
 * Visual/analytics frames coalesce by `entityKey` so a slow consumer never
 * queues unbounded work. Execution-critical (P0) frames are never coalesced and
 * an eviction of any P0 frame forces a resync rather than a silent drop.
 */
export class FrameBatcher {
  private readonly buckets: [Map<string, DecodedFrame>, Map<string, DecodedFrame>, Map<string, DecodedFrame>, Map<string, DecodedFrame>] = [
    new Map(),
    new Map(),
    new Map(),
    new Map(),
  ];
  private readonly lastFlush: [number, number, number, number] = [
    Number.NEGATIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
  ];
  private total = 0;
  private p0Sequence = 0;

  constructor(private readonly options: FrameBatcherOptions) {}

  size(): number {
    return this.total;
  }

  enqueue(frame: DecodedFrame): EnqueueResult {
    const bucket = this.buckets[frame.priority];
    // P0 (execution/order lifecycle) transitions are never coalesced: an
    // intermediate SUBMITTED → FILLED must stay observable.
    const key = frame.priority === 0 ? `${frame.entityKey}#${this.p0Sequence++}` : frame.entityKey;
    if (frame.priority !== 0 && bucket.has(key)) {
      bucket.set(key, frame);
      return { replaced: true, forcedResync: false };
    }
    let forcedResync = false;
    if (this.total >= this.options.capacity) {
      forcedResync = this.evictOne();
    }
    bucket.set(key, frame);
    this.total += 1;
    return { replaced: false, forcedResync };
  }

  private evictOne(): boolean {
    // Drop lowest-priority (metadata first) before visual, never deliberately
    // drop P0; if only P0 remains, force a resync for the dropped frame.
    for (let priority = 3 as Priority; priority >= 1; priority = (priority - 1) as Priority) {
      const bucket = this.buckets[priority];
      if (bucket.size > 0) {
        const oldestKey = bucket.keys().next().value as string;
        bucket.delete(oldestKey);
        this.total -= 1;
        return false;
      }
    }
    const p0 = this.buckets[0];
    if (p0.size > 0) {
      const oldestKey = p0.keys().next().value as string;
      p0.delete(oldestKey);
      this.total -= 1;
      return true;
    }
    return false;
  }

  /** Frames whose per-priority interval has elapsed; ordered P0 → P3. */
  drainDue(now: number): DecodedFrame[] {
    const out: DecodedFrame[] = [];
    for (let priority = 0 as Priority; priority <= 3; priority = (priority + 1) as Priority) {
      const bucket = this.buckets[priority];
      if (bucket.size === 0) continue;
      const interval = this.options.flushMs[priority];
      if (now - this.lastFlush[priority] < interval) continue;
      this.lastFlush[priority] = now;
      out.push(...bucket.values());
      this.total -= bucket.size;
      bucket.clear();
    }
    return out;
  }

  drainAll(): DecodedFrame[] {
    const out: DecodedFrame[] = [];
    for (let priority = 0 as Priority; priority <= 3; priority = (priority + 1) as Priority) {
      const bucket = this.buckets[priority];
      out.push(...bucket.values());
      this.total -= bucket.size;
      bucket.clear();
    }
    return out;
  }
}
