import type { DepthLevel } from "../contracts/market";

export interface EnrichedLevel extends DepthLevel {
  readonly cumulativeSize: number;
  readonly cumulativeNotional: number;
}

function sanitize(levels: readonly DepthLevel[], descending: boolean, capacity: number): DepthLevel[] {
  const clean = levels.filter(
    (level) => Number.isFinite(level.price) && Number.isFinite(level.size) && level.price > 0 && level.size > 0,
  );
  clean.sort((a, b) => (descending ? b.price - a.price : a.price - b.price));
  return clean.slice(0, capacity);
}

/** Cumulative size/notional from the top of book downward; bounded output. */
export function enrichDepth(levels: readonly DepthLevel[], capacity = 200): EnrichedLevel[] {
  const out: EnrichedLevel[] = [];
  let cumulativeSize = 0;
  let cumulativeNotional = 0;
  for (const level of levels.slice(0, capacity)) {
    cumulativeSize += level.size;
    cumulativeNotional += level.size * level.price;
    out.push({ ...level, cumulativeSize, cumulativeNotional });
  }
  return out;
}

export interface DepthSnapshot {
  readonly bids: readonly DepthLevel[];
  readonly asks: readonly DepthLevel[];
  readonly slot: number | null;
}

/** Bounded local order book with top-of-book and imbalance helpers. */
export class DepthBookStore {
  private bids: DepthLevel[] = [];
  private asks: DepthLevel[] = [];
  private slot: number | null = null;

  constructor(readonly capacity = 200) {}

  applySnapshot(snapshot: DepthSnapshot): void {
    this.bids = sanitize(snapshot.bids, true, this.capacity);
    this.asks = sanitize(snapshot.asks, false, this.capacity);
    this.slot = snapshot.slot;
  }

  clear(): void {
    this.bids = [];
    this.asks = [];
    this.slot = null;
  }

  get length(): number {
    return this.bids.length + this.asks.length;
  }

  getSlot(): number | null {
    return this.slot;
  }

  getBids(): readonly DepthLevel[] {
    return this.bids;
  }

  getAsks(): readonly DepthLevel[] {
    return this.asks;
  }

  bidLevels(): EnrichedLevel[] {
    return enrichDepth(this.bids, this.capacity);
  }

  askLevels(): EnrichedLevel[] {
    return enrichDepth(this.asks, this.capacity);
  }

  bestBid(): number | null {
    return this.bids[0]?.price ?? null;
  }

  bestAsk(): number | null {
    return this.asks[0]?.price ?? null;
  }

  mid(): number | null {
    const bid = this.bestBid();
    const ask = this.bestAsk();
    if (bid === null || ask === null) return null;
    return (bid + ask) / 2;
  }

  spreadBps(): number | null {
    const bid = this.bestBid();
    const ask = this.bestAsk();
    const mid = this.mid();
    if (bid === null || ask === null || mid === null || mid === 0) return null;
    return ((ask - bid) / mid) * 10_000;
  }

  /** Positive = bid-heavy, negative = ask-heavy, over `levels` deep. */
  imbalancePct(levels = 10): number | null {
    const bidSize = this.bids.slice(0, levels).reduce((sum, level) => sum + level.size, 0);
    const askSize = this.asks.slice(0, levels).reduce((sum, level) => sum + level.size, 0);
    const total = bidSize + askSize;
    if (total === 0) return null;
    return ((bidSize - askSize) / total) * 100;
  }
}
