import { describe, expect, it } from "vitest";
import { chartEntityKeyFor } from "./ChartPanel";

describe("chartEntityKeyFor", () => {
  it("targets the selected instrument", () => {
    expect(chartEntityKeyFor({ chain: "base", address: "0xabc", symbol: "TKN" })).toBe(
      "ohlcv:base:0xabc",
    );
  });

  it("keeps the neutral default with no selection", () => {
    expect(chartEntityKeyFor(null)).toBe("ohlcv:default");
  });

  it("honours an explicit embed override and ignores an empty one", () => {
    expect(
      chartEntityKeyFor({ chain: "base", address: "0xabc", symbol: "TKN" }, "ohlcv:BASE:SOL"),
    ).toBe("ohlcv:BASE:SOL");
    expect(chartEntityKeyFor(null, "")).toBe("ohlcv:default");
  });
});
