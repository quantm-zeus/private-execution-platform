import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { workspaceError } from "../../core/errors";
import type { CommandClient } from "../../transport/command";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import type { LimitOrderView, TradeIntentView } from "../../contracts/execution";
import LimitsPanel from "./LimitsPanel";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

class FakeCommandClient implements CommandClient {
  readonly calls: { op: string; payload: unknown }[] = [];
  private readonly handlers: Record<string, (payload: unknown) => unknown>;

  constructor(handlers: Record<string, (payload: unknown) => unknown>) {
    this.handlers = handlers;
  }

  async send<T>(op: string, payload: unknown): Promise<T> {
    this.calls.push({ op, payload });
    const handler = this.handlers[op];
    if (!handler) throw workspaceError("server", `No handler for ${op}.`);
    return (await handler(payload)) as T;
  }

  count(op: string): number {
    return this.calls.filter((call) => call.op === op).length;
  }
}

interface StoreOptions {
  readonly command: CommandClient;
  readonly tradingEnabled?: boolean;
}

async function readyStore(options: StoreOptions) {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1000,
    command: options.command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { limits: true, portfolio: true },
      trading_enabled: options.tradingEnabled ?? true,
      kill_switch: { enabled: false, reason: null },
      chains: [],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.reload();
  await flush();
  return store;
}

function makeIntent(overrides: Partial<TradeIntentView> = {}): TradeIntentView {
  return {
    id: "intent-1",
    chain: "base",
    tokenIn: "0x1111111111111111111111111111111111111111",
    tokenOut: "0x2222222222222222222222222222222222222222",
    side: "buy",
    amountType: "usd",
    amount: "5",
    orderType: "limit",
    limitPrice: "2.50",
    maxBuyTaxBps: 100,
    maxSellTaxBps: null,
    maxPriceImpactBps: 50,
    maxSlippageBps: 50,
    maxTotalCostUsd: 6,
    allowPartialFill: true,
    expiryMs: 1_700_000_000_000,
    ...overrides,
  };
}

function makeOrder(overrides: Partial<LimitOrderView> = {}): LimitOrderView {
  return {
    orderId: "order-1",
    intent: makeIntent(),
    state: "ACTIVE",
    filledAmount: "0",
    remainingAmount: "5",
    fills: [],
    createdAtMs: 900,
    updatedAtMs: 950,
    nextActionMs: null,
    failureReason: null,
    ...overrides,
  };
}

function renderPanel(store: ReturnType<typeof createWorkspaceStore>) {
  return render(() => (
    <WorkspaceProvider store={store}>
      <LimitsPanel />
    </WorkspaceProvider>
  ));
}

describe("LimitsPanel", () => {
  afterEach(() => cleanup());

  it("renders filled and remaining for a partially filled order", async () => {
    const client = new FakeCommandClient({
      get_orders: () => ({
        orders: [
          makeOrder({
            state: "PARTIALLY_FILLED",
            filledAmount: "1.5",
            remainingAmount: "3.5",
            fills: [
              { executionId: "0xexecution000000000000000000000000000000", amountIn: "1.5", amountOut: "3.7", atMs: 980 },
            ],
          }),
        ],
      }),
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    expect(screen.getByText(/Filled: 1\.5/)).toBeTruthy();
    expect(screen.getByText(/Remaining: 3\.5/)).toBeTruthy();
    expect(screen.getByText(/partial fill: filled/i)).toBeTruthy();
    expect(screen.getByText(/stays active until it fills/i)).toBeTruthy();
  });

  it("renders UNKNOWN with a reconcile action and never auto-retries", async () => {
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [makeOrder({ state: "UNKNOWN" })] }),
      get_order: () => ({ order: makeOrder({ state: "ACTIVE" }) }),
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    expect(screen.getByText("UNKNOWN")).toBeTruthy();
    expect(screen.getByText(/no blind retry/i)).toBeTruthy();
    // Rendering an unknown order must not trigger a blind backend re-read.
    expect(client.count("get_order")).toBe(0);

    fireEvent.click(screen.getByRole("button", { name: /reconcile/i }));
    await flush();
    expect(client.count("get_order")).toBe(1);
  });

  it("disables place and cancel with a reason when trading is disabled", async () => {
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [makeOrder({ state: "ACTIVE" })] }),
    });
    const store = await readyStore({ command: client, tradingEnabled: false });
    renderPanel(store);
    await flush();

    const place = screen.getByRole("button", { name: /place limit order/i });
    expect((place as HTMLButtonElement).disabled).toBe(true);

    const cancel = screen.getByRole("button", { name: /^cancel$/i });
    expect((cancel as HTMLButtonElement).disabled).toBe(true);

    expect(screen.getAllByText(/trading is disabled/i).length).toBeGreaterThan(0);
  });

  it("renders an empty state when there are no orders", async () => {
    const client = new FakeCommandClient({ get_orders: () => ({ orders: [] }) });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    expect(screen.getByText(/no limit orders/i)).toBeTruthy();
  });
});
