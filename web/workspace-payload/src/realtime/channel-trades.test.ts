import { describe, expect, it } from "vitest";
import { decodeInnerFrame } from "./decoder";
import type { RealtimeChannel } from "./types";

/**
 * `RealtimeChannel` also has a `"trades"` member. It is a transport channel and
 * is deliberately untouched by the dock's DockTab change (which removed the UI
 * `trades` tab). This guards against a future cleanup conflating the two
 * namespaces.
 */
describe("RealtimeChannel trades transport member", () => {
  it("still accepts and decodes a `trades` frame", () => {
    const channel: RealtimeChannel = "trades";
    expect(channel).toBe("trades");
    const bytes = new TextEncoder().encode(
      JSON.stringify({
        op: "snapshot",
        channel: "trades",
        entity_key: "trades:SOL",
        payload: { trades: [] },
      }),
    );
    const frame = decodeInnerFrame(bytes, 1);
    expect(frame.channel).toBe("trades");
    // P1 visual lane, unchanged by the dock IA correction.
    expect(frame.priority).toBe(1);
  });
});
