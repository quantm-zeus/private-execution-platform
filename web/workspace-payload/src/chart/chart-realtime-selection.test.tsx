import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@solidjs/testing-library";
import type { Accessor } from "solid-js";
import ChartPanel from "./ChartPanel";
import { RealtimeFeedProvider } from "../realtime/feed-context";
import type { RealtimeFeed } from "../realtime/use-realtime";
import type { DecodedFrame } from "../realtime/types";
import { WorkspaceProvider, createWorkspaceStore, type WorkspaceStore } from "../state/session";
import { WorkstationProvider } from "../state/workstation";
import { parseWorkspaceSession } from "../transport/bootstrap";
import type { CommandClient } from "../transport/command";
import type { ConnectionStatus } from "../core/types";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const A = { chain: "base", address: "0xAAA", symbol: "AAA" } as const;
const B = { chain: "base", address: "0xBBB", symbol: "BBB" } as const;

function candle(timeMs: number, close: number) {
  return { time_ms: timeMs, open: close - 1, high: close + 1, low: close - 2, close, volume: 10 };
}

function snapshot(entityKey: string, bars = 12): DecodedFrame {
  const start = Math.floor(Date.now() / 60_000) * 60_000 - (bars - 1) * 60_000;
  return {
    seq: 1,
    op: "snapshot",
    channel: "ohlcv",
    priority: 1,
    entityKey,
    slot: 1,
    sourceAgeMs: 0,
    serverTimeMs: null,
    payload: {
      timeframe: "1m",
      candles: Array.from({ length: bars }, (_, index) => candle(start + index * 60_000, 100 + index)),
    },
  };
}

/** A feed the test can push already-decrypted frames into. */
function fakeFeed(): RealtimeFeed & { emit: (frames: DecodedFrame[]) => void } {
  const handlers = new Set<(frames: DecodedFrame[]) => void>();
  const status: Accessor<ConnectionStatus> = () => ({
    phase: "live",
    lastFrameAtMs: Date.now(),
    attempt: 0,
    nextRetryAtMs: null,
    reason: null,
  });
  return {
    status,
    started: () => true,
    subscribe: (handler) => {
      handlers.add(handler);
      return () => handlers.delete(handler);
    },
    emit: (frames) => {
      for (const handler of handlers) handler(frames);
    },
  };
}

function createStore(): { store: WorkspaceStore; commands: string[] } {
  const commands: string[] = [];
  const command: CommandClient = {
    async send<T>(op: string): Promise<T> {
      commands.push(op);
      return { accepted: true } as T;
    },
  };
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { realtime: true, market: true, chart: true },
      trading_enabled: false,
      kill_switch: { enabled: false, reason: null },
      chains: [],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.setCommand(command);
  store.reload();
  return { store, commands };
}

function renderChart(store: WorkspaceStore, feed: RealtimeFeed) {
  return render(() => (
    <WorkspaceProvider store={store}>
      <WorkstationProvider ws={store}>
        <RealtimeFeedProvider feed={feed}>
          <ChartPanel />
        </RealtimeFeedProvider>
      </WorkstationProvider>
    </WorkspaceProvider>
  ));
}

describe("selected-token realtime chart delivery", () => {
  afterEach(() => cleanup());

  it("renders candles for the exact selected entity and leaves AWAITING FEED behind", async () => {
    const { store } = createStore();
    const feed = fakeFeed();
    store.setSelectedInstrument({ ...A });
    await flush();
    renderChart(store, feed);
    await flush();

    const target = () => screen.getByTestId("chart-target");
    expect(target().textContent).toContain("AWAITING FEED");
    expect(target().getAttribute("data-candles")).toBe("0");

    feed.emit([snapshot("ohlcv:base:0xAAA")]);
    await flush();

    expect(Number(target().getAttribute("data-candles"))).toBeGreaterThan(0);
    expect(target().textContent).toContain("LOCAL DATA");
  });

  it("never lets stale token A frames make token B look live", async () => {
    const { store } = createStore();
    const feed = fakeFeed();
    store.setSelectedInstrument({ ...A });
    await flush();
    renderChart(store, feed);
    await flush();

    feed.emit([snapshot("ohlcv:base:0xAAA")]);
    await flush();
    expect(Number(screen.getByTestId("chart-target").getAttribute("data-candles"))).toBeGreaterThan(0);

    store.setSelectedInstrument({ ...B });
    await flush();
    // A late frame for the previous token must not satisfy the new selection.
    feed.emit([snapshot("ohlcv:base:0xAAA")]);
    await flush();

    expect(screen.getByTestId("chart-target").getAttribute("data-candles")).toBe("0");
    expect(screen.getByTestId("chart-target").textContent).toContain("AWAITING FEED");
  });

  it("binds the encrypted realtime target to the exact selected token", async () => {
    const { store, commands } = createStore();
    const feed = fakeFeed();
    store.setSelectedInstrument({ ...A });
    await flush();
    renderChart(store, feed);
    await flush();
    store.setSelectedInstrument({ ...B });
    await flush();

    expect(commands.filter((op) => op === "set_realtime_target")).toHaveLength(2);
  });
});
