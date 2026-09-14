import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { TradePanel } from "./TradePanel";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import type { CommandClient } from "../../transport/command";
import { WorkspaceError } from "../../core/types";
import type { QuotePreview } from "../../contracts/execution";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const quote: QuotePreview = {
  quoteId: "q-1",
  intent: {
    id: "intent-1",
    chain: "base",
    tokenIn: "USDC",
    tokenOut: "SOL",
    side: "buy",
    amountType: "usd",
    amount: "100",
    orderType: "market",
    limitPrice: null,
    maxBuyTaxBps: null,
    maxSellTaxBps: null,
    maxPriceImpactBps: 150,
    maxSlippageBps: 100,
    maxTotalCostUsd: null,
    allowPartialFill: true,
    expiryMs: null,
  },
  route: [
    { index: 0, venue: "aerodrome", kind: "direct", tokenIn: "USDC", tokenOut: "SOL", sharePct: 100 },
  ],
  economics: {
    grossOutput: 98.5,
    netOutput: 96.2,
    taxBps: 50,
    dexFeeBps: 30,
    gasUsd: 0.42,
    priceImpactBps: 12,
    expectedSlippageBps: 20,
    mevRiskBps: 5,
    failureProbability: 0.01,
    minReceived: "95.0",
  },
  slot: 123,
  sourceAgeMs: 25,
  expiresAtMs: null,
  revalidationRequired: false,
};

function sessionPayload(execute: boolean, tradingEnabled: boolean) {
  return {
    protocol_version: 1,
    capabilities: { preview: true, execute, market: true },
    trading_enabled: tradingEnabled,
    kill_switch: { enabled: false, reason: null },
    chains: [{ id: "base", display: "Base", enabled: true }],
    session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
    server_time_ms: 1_699_999_000_000,
  };
}

function makeStore(command: CommandClient, execute = true, tradingEnabled = false) {
  return createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command,
    session: parseWorkspaceSession(sessionPayload(execute, tradingEnabled)),
  });
}

const quotingClient: CommandClient = {
  async send<T>(op: string): Promise<T> {
    if (op === "preview_market_order") return quote as unknown as T;
    throw new Error(`unexpected op ${op}`);
  },
};

const rejectingClient: CommandClient = {
  async send<T>(): Promise<T> {
    throw new WorkspaceError({
      code: "capability_missing",
      message: "Private command channel is not available.",
      retryable: false,
    });
  },
};

describe("TradePanel", () => {
  afterEach(() => cleanup());

  it("renders full net economics and route legs from a preview", async () => {
    const store = makeStore(quotingClient);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await flush();
    expect(screen.getByText("Simulated net output (execution truth)")).toBeTruthy();
    expect(screen.getByText(/96\.2/)).toBeTruthy();
    expect(screen.getByText("aerodrome")).toBeTruthy();
    expect(screen.getByText(/slot 123/)).toBeTruthy();
  });

  it("keeps execution disabled while the trading gate is off", async () => {
    const store = makeStore(quotingClient, true, false);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await flush();
    const buy = screen.getByRole("button", { name: /execute buy/i });
    expect((buy as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/Trading is disabled by the global kill switch/i)).toBeTruthy();
  });

  it("renders unknown economics as an em dash, never a zero", async () => {
    const emptyQuote: QuotePreview = {
      ...quote,
      economics: {
        ...quote.economics,
        netOutput: null,
        gasUsd: null,
        minReceived: null,
      },
    };
    const client: CommandClient = {
      async send<T>(): Promise<T> {
        return emptyQuote as unknown as T;
      },
    };
    const store = makeStore(client);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await flush();
    const row = document.querySelector('[data-key="net"]');
    expect(row?.textContent).toContain("—");
    expect(row?.textContent).not.toContain("0.00");
  });

  it("shows an unavailable/error state when the preview command is missing", async () => {
    const store = makeStore(rejectingClient);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await flush();
    expect(screen.getAllByText(/not deployed|not available/i).length).toBeGreaterThan(0);
  });

  it("does not preview without a positive amount", async () => {
    let calls = 0;
    const counting: CommandClient = {
      async send<T>(op: string): Promise<T> {
        calls++;
        return quote as unknown as T;
      },
    };
    const store = makeStore(counting);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await flush();
    expect(calls).toBe(0);
  });
});
