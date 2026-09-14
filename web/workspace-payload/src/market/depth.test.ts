import { describe, expect, it } from "vitest";
import { DepthBookStore, enrichDepth } from "./depth";

describe("enrichDepth", () => {
  it("accumulates size and notional from the top of book", () => {
    const out = enrichDepth([
      { price: 10, size: 2 },
      { price: 9, size: 3 },
    ]);
    expect(out[0]).toMatchObject({ cumulativeSize: 2, cumulativeNotional: 20 });
    expect(out[1]).toMatchObject({ cumulativeSize: 5, cumulativeNotional: 47 });
  });

  it("applies the capacity bound", () => {
    const levels = Array.from({ length: 10 }, (_, i) => ({ price: 10 - i, size: 1 }));
    expect(enrichDepth(levels, 3)).toHaveLength(3);
  });
});

describe("DepthBookStore", () => {
  it("sorts books and computes top-of-book metrics", () => {
    const store = new DepthBookStore(50);
    store.applySnapshot({
      bids: [
        { price: 9, size: 1 },
        { price: 10, size: 2 },
      ],
      asks: [
        { price: 12, size: 1 },
        { price: 11, size: 3 },
      ],
      slot: 42,
    });
    expect(store.bestBid()).toBe(10);
    expect(store.bestAsk()).toBe(11);
    expect(store.mid()).toBe(10.5);
    expect(store.spreadBps()).toBeCloseTo((1 / 10.5) * 10_000, 5);
    expect(store.getSlot()).toBe(42);
  });

  it("drops non-positive and non-finite levels", () => {
    const store = new DepthBookStore(50);
    store.applySnapshot({
      bids: [
        { price: 0, size: 5 },
        { price: 10, size: -1 },
        { price: Number.NaN, size: 1 },
        { price: 9, size: 2 },
      ],
      asks: [],
      slot: null,
    });
    expect(store.getBids()).toEqual([{ price: 9, size: 2 }]);
  });

  it("computes imbalance over the requested depth", () => {
    const store = new DepthBookStore(50);
    store.applySnapshot({
      bids: [{ price: 10, size: 8 }],
      asks: [{ price: 11, size: 2 }],
      slot: null,
    });
    expect(store.imbalancePct(10)).toBeCloseTo(60, 5);
  });

  it("returns null metrics for an empty book", () => {
    const store = new DepthBookStore(50);
    expect(store.bestBid()).toBeNull();
    expect(store.mid()).toBeNull();
    expect(store.spreadBps()).toBeNull();
    expect(store.imbalancePct()).toBeNull();
  });
});
