import { CandleRingBuffer, type CandleLike } from "./ring-buffer";

export interface Timeframe {
  readonly id: string;
  readonly label: string;
  readonly ms: number;
}

export const TIMEFRAMES: readonly Timeframe[] = [
  { id: "1s", label: "1s", ms: 1_000 },
  { id: "5s", label: "5s", ms: 5_000 },
  { id: "15s", label: "15s", ms: 15_000 },
  { id: "1m", label: "1m", ms: 60_000 },
  { id: "5m", label: "5m", ms: 300_000 },
  { id: "15m", label: "15m", ms: 900_000 },
  { id: "1h", label: "1h", ms: 3_600_000 },
  { id: "4h", label: "4h", ms: 14_400_000 },
  { id: "1d", label: "1d", ms: 86_400_000 },
];

export function timeframeById(id: string): Timeframe | undefined {
  return TIMEFRAMES.find((timeframe) => timeframe.id === id);
}

/**
 * Timeframes the authoritative paths can actually serve: the canonical
 * `get_chart` windows and the Pro period bar. Seconds exist only as local
 * aggregation primitives and are rejected by the backend realtime target, so
 * the shared workstation timeframe must never accept them (a determinate
 * rejection would otherwise wedge the target binding).
 */
export const SERVED_TIMEFRAME_IDS: readonly string[] = ["1m", "5m", "15m", "1h", "4h", "1d"];

export function isServedTimeframe(id: string): boolean {
  return SERVED_TIMEFRAME_IDS.includes(id);
}

function isValidCandle(candle: CandleLike): boolean {
  return (
    Number.isFinite(candle.timeMs) &&
    Number.isFinite(candle.open) &&
    Number.isFinite(candle.high) &&
    Number.isFinite(candle.low) &&
    Number.isFinite(candle.close) &&
    Number.isFinite(candle.volume) &&
    candle.high >= candle.low &&
    candle.volume >= 0
  );
}

/** Roll base candles up into a coarser timeframe using floor bucketing. */
export function aggregateCandles(
  candles: readonly CandleLike[],
  timeframeMs: number,
): CandleLike[] {
  if (!Number.isSafeInteger(timeframeMs) || timeframeMs <= 0) {
    throw new Error("timeframe must be a positive integer");
  }
  const out: CandleLike[] = [];
  let current: { timeMs: number; open: number; high: number; low: number; close: number; volume: number } | null =
    null;
  for (const candle of candles) {
    if (!isValidCandle(candle)) continue;
    const bucket = Math.floor(candle.timeMs / timeframeMs) * timeframeMs;
    if (current === null || bucket !== current.timeMs) {
      if (current) out.push(current);
      current = {
        timeMs: bucket,
        open: candle.open,
        high: candle.high,
        low: candle.low,
        close: candle.close,
        volume: candle.volume,
      };
    } else {
      current.high = Math.max(current.high, candle.high);
      current.low = Math.min(current.low, candle.low);
      current.close = candle.close;
      current.volume += candle.volume;
    }
  }
  if (current) out.push(current);
  return out;
}

/**
 * Bounded, time-ordered candle series. Out-of-order or duplicate frames never
 * grow the buffer or corrupt ordering; the newest bar is replaced in place.
 */
export class CandleSeries {
  private readonly buffer: CandleRingBuffer;

  constructor(
    readonly timeframeMs: number,
    capacity = 4_096,
  ) {
    this.buffer = new CandleRingBuffer(capacity);
  }

  get length(): number {
    return this.buffer.length;
  }

  get capacity(): number {
    return this.buffer.capacity;
  }

  clear(): void {
    this.buffer.clear();
  }

  /** Replace the series with an authoritative snapshot (sorted, deduped). */
  applySnapshot(candles: readonly CandleLike[]): void {
    const sorted = candles
      .filter(isValidCandle)
      .slice()
      .sort((a, b) => a.timeMs - b.timeMs);
    const deduped: CandleLike[] = [];
    for (const candle of sorted) {
      const last = deduped[deduped.length - 1];
      if (last && last.timeMs === candle.timeMs) deduped[deduped.length - 1] = candle;
      else deduped.push(candle);
    }
    this.buffer.clear();
    for (const candle of deduped) this.buffer.push(candle);
  }

  /** Apply a single delta bar. Returns false when it was stale/out-of-order. */
  upsert(candle: CandleLike): boolean {
    if (!isValidCandle(candle)) return false;
    const last = this.buffer.last();
    if (!last) {
      this.buffer.push(candle);
      return true;
    }
    if (candle.timeMs === last.timeMs) {
      this.buffer.replaceLast(candle);
      return true;
    }
    if (candle.timeMs > last.timeMs) {
      this.buffer.push(candle);
      return true;
    }
    return false;
  }

  toArray(): CandleLike[] {
    return this.buffer.toArray();
  }

  last(): CandleLike | undefined {
    return this.buffer.last();
  }

  range(fromMs: number, toMs: number): CandleLike[] {
    const out: CandleLike[] = [];
    for (let i = 0; i < this.buffer.length; i++) {
      const candle = this.buffer.at(i)!;
      if (candle.timeMs >= fromMs && candle.timeMs <= toMs) out.push(candle);
    }
    return out;
  }
}
