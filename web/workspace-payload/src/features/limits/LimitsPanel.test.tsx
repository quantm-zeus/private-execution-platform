import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { bytesToBase64, utf8Encode } from "../../core/base64";
import { workspaceError } from "../../core/errors";
import type { CommandClient, CommandSendOptions } from "../../transport/command";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import { WebCryptoDecryptor } from "../../realtime/decryptor";
import { sealerFromBase64 } from "../../realtime/sealer";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import type { LimitOrderView, TradeIntentView } from "../../contracts/execution";
import LimitsPanel from "./LimitsPanel";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/** Every fixture that exercises a mutation advertises the live realtime feed. */
function liveConnection() {
  return {
    phase: "live" as const,
    lastFrameAtMs: 1_000,
    attempt: 0,
    nextRetryAtMs: null,
    reason: null,
  };
}

class FakeCommandClient implements CommandClient {
  readonly calls: { op: string; payload: unknown; options?: CommandSendOptions }[] = [];
  handlers: Record<string, (payload: unknown) => unknown>;

  constructor(handlers: Record<string, (payload: unknown) => unknown>) {
    this.handlers = handlers;
  }

  async send<T>(op: string, payload: unknown, options?: CommandSendOptions): Promise<T> {
    this.calls.push({ op, payload, options });
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
  /** When false, no chain quote token / selection is advertised. */
  readonly target?: boolean;
}

const LIMIT_QUOTE_TOKEN = "0x1111111111111111111111111111111111111111";
const LIMIT_SELECTED_TOKEN = "0x2222222222222222222222222222222222222222";

async function readyStore(options: StoreOptions) {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1000,
    command: options.command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      // Limits place/cancel are capital-committing: advertise + mark live.
      capabilities: { limits: true, portfolio: true, realtime: true },
      trading_enabled: options.tradingEnabled ?? true,
      kill_switch: { enabled: false, reason: null },
      chains:
        options.target === false
          ? []
          : [
              {
                id: "base",
                display: "Base",
                enabled: true,
                native_token: LIMIT_QUOTE_TOKEN,
              },
            ],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.reload();
  await flush();
  store.setConnection(liveConnection());
  if (options.target !== false) {
    store.setSelectedInstrument({ chain: "base", address: LIMIT_SELECTED_TOKEN, symbol: "TKN" });
  }
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

  it("includes the resolved chain and tokens in the place_limit_order payload", async () => {
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [] }),
      place_limit_order: () => ({ order_id: "ord-1" }),
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    fireEvent.input(screen.getByLabelText("Limit net price"), { target: { value: "2.5" } });
    fireEvent.input(screen.getByLabelText("Limit amount"), { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: /place limit order/i }));
    await flush();

    const call = client.calls.find((entry) => entry.op === "place_limit_order");
    expect(call?.payload).toMatchObject({
      chain: "base",
      token_in: LIMIT_QUOTE_TOKEN,
      token_out: LIMIT_SELECTED_TOKEN,
    });
  });

  it("fails closed with no resolved target and sends no place_limit_order", async () => {
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [] }),
      place_limit_order: () => ({ order_id: "ord-1" }),
    });
    const store = await readyStore({ command: client, target: false });
    renderPanel(store);
    await flush();

    fireEvent.input(screen.getByLabelText("Limit net price"), { target: { value: "2.5" } });
    fireEvent.input(screen.getByLabelText("Limit amount"), { target: { value: "5" } });
    const place = screen.getByRole("button", { name: /place limit order/i }) as HTMLButtonElement;
    expect(place.disabled).toBe(true);
    fireEvent.click(place);
    await flush();

    expect(client.count("place_limit_order")).toBe(0);
    expect(screen.getByText(/select a token in discover/i)).toBeTruthy();
  });

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

  it("refuses a non-positive intent client-side without calling the backend", async () => {
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [] }),
      place_limit_order: () => ({ order_id: "ord-1" }),
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    fireEvent.input(screen.getByLabelText("Limit net price"), { target: { value: "2.5" } });
    fireEvent.input(screen.getByLabelText("Limit amount"), { target: { value: "-5" } });
    fireEvent.click(screen.getByRole("button", { name: /place limit order/i }));
    await flush();

    expect(client.count("place_limit_order")).toBe(0);
    expect(screen.getByText(/positive amount/i)).toBeTruthy();
  });

  it("reuses the idempotency key on retry and rotates it after success", async () => {
    let fail = true;
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [] }),
      place_limit_order: () => {
        if (fail) throw workspaceError("network", "offline");
        return { order_id: "ord-1" };
      },
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    fireEvent.input(screen.getByLabelText("Limit net price"), { target: { value: "2.5" } });
    fireEvent.input(screen.getByLabelText("Limit amount"), { target: { value: "5" } });

    const placeButton = () => screen.getByRole("button", { name: /place limit order/i });
    fireEvent.click(placeButton());
    await flush();
    fireEvent.click(placeButton());
    await flush();

    const keys = client.calls
      .filter((call) => call.op === "place_limit_order")
      .map((call) => call.options?.idempotencyKey);
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBeTruthy();
    expect(keys[1]).toBe(keys[0]);

    // A new logical submission after success must not be deduped by the backend.
    fail = false;
    fireEvent.click(placeButton());
    await flush();
    // The successful submission still reused the retry key (correct idempotency);
    // the *next* submission must rotate to a fresh key.
    fireEvent.click(placeButton());
    await flush();
    const afterSuccess = client.calls
      .filter((call) => call.op === "place_limit_order")
      .map((call) => call.options?.idempotencyKey);
    expect(afterSuccess[2]).toBe(afterSuccess[1]);
    expect(afterSuccess[3]).toBeTruthy();
    expect(afterSuccess[3]).not.toBe(afterSuccess[2]);
  });

  it("rotates the idempotency key after a determinate rejection but keeps it on an ambiguous failure", async () => {
    let mode: "rejected" | "network" | "freshness" = "rejected";
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [] }),
      place_limit_order: () => {
        if (mode === "rejected") {
          // A non-retryable rejection proves no commit: a new attempt is a
          // genuinely new logical order with a fresh key.
          throw workspaceError("freshness", "state changed", { retryable: false });
        }
        throw workspaceError(mode, mode === "freshness" ? "stale" : "offline");
      },
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    fireEvent.input(screen.getByLabelText("Limit net price"), { target: { value: "2.5" } });
    fireEvent.input(screen.getByLabelText("Limit amount"), { target: { value: "5" } });
    const placeButton = () => screen.getByRole("button", { name: /place limit order/i });
    const keys = () =>
      client.calls.filter((call) => call.op === "place_limit_order").map((call) => call.options?.idempotencyKey);

    fireEvent.click(placeButton());
    await flush();
    // A determinate rejection definitely did not commit, so the next identical
    // attempt is a genuinely new logical order with a fresh key.
    fireEvent.click(placeButton());
    await flush();
    expect(keys()).toHaveLength(2);
    expect(keys()[1]).not.toBe(keys()[0]);

    // An ambiguous transport failure keeps the key so a retry dedupes.
    mode = "network";
    const before = keys().length;
    fireEvent.click(placeButton());
    await flush();
    fireEvent.click(placeButton());
    await flush();
    expect(keys()[before + 1]).toBe(keys()[before]);

    // A *retryable* freshness rejection is ambiguous too: the order may have
    // committed, so rotating the key here would risk a duplicate.
    mode = "freshness";
    const retryableBefore = keys().length;
    fireEvent.click(placeButton());
    await flush();
    fireEvent.click(placeButton());
    await flush();
    expect(keys()[retryableBefore + 1]).toBe(keys()[retryableBefore]);
  });

  it("renders an empty state when there are no orders", async () => {
    const client = new FakeCommandClient({ get_orders: () => ({ orders: [] }) });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    expect(screen.getByText(/no limit orders/i)).toBeTruthy();
  });

  it("loads orders once bootstrap resolves, even when mounted before it", async () => {
    const rawKey = new Uint8Array(32).fill(7);
    const keyB64 = bytesToBase64(rawKey);
    let captured: RequestInit | null = null;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    // Bootstrap stays pending until the test releases it; the request is sealed
    // as an octet-stream envelope and the response is sealed back at its
    // sequence with the request id echoed.
    const fetchFn = (async (_url: string, init: RequestInit) => {
      captured = init;
      await gate;
      const envelope = JSON.parse(new TextDecoder().decode(init.body as Uint8Array)) as {
        sequence: number;
      };
      const decryptor = await WebCryptoDecryptor.fromRawKey(rawKey, "kid-1");
      const request = JSON.parse(new TextDecoder().decode(await decryptor.decrypt(envelope as never))) as {
        request_id: string;
      };
      const sealer = await sealerFromBase64(keyB64);
      const sealed = await sealer.seal(
        { kid: "kid-1", sequence: envelope.sequence },
        utf8Encode(
          JSON.stringify({
            protocol_version: 1,
            capabilities: { limits: true, portfolio: true },
            trading_enabled: true,
            kill_switch: { enabled: false, reason: null },
            chains: [],
            session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
            server_time_ms: 1_699_999_000_000,
            request_id: request.request_id,
          }),
        ),
      );
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            kid: "kid-1",
            sequence: envelope.sequence,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
          }),
      } as Response;
    }) as unknown as typeof fetch;

    const client = new FakeCommandClient({ get_orders: () => ({ orders: [] }) });
    const store = createWorkspaceStore({
      manualClock: true,
      clock: () => 1000,
      command: client,
      hostKeyProvider: async () => ({ kid: "kid-1", c2sKeyB64: keyB64, s2cKeyB64: keyB64 }),
      fetchFn,
    });
    // Begin bootstrap but do not let it resolve: capabilities are all-false.
    store.reload();
    renderPanel(store);
    await flush();
    for (let i = 0; i < 10 && captured === null; i += 1) await flush();
    expect(captured).not.toBeNull();
    expect(client.count("get_orders")).toBe(0);

    // Bootstrap resolves with the limits capability: the panel must load now,
    // not stay on an unqueried "no limit orders".
    release();
    await flush();
    await flush();
    for (let i = 0; i < 20 && client.count("get_orders") === 0; i += 1) await flush();
    expect(client.count("get_orders")).toBe(1);
  });

  it("surfaces an ambiguous place as UNKNOWN with an idempotent retry and a two-step discard", async () => {
    let mode: "network" | "ok" = "network";
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [] }),
      place_limit_order: () => {
        if (mode === "network") throw workspaceError("network", "offline");
        return { order_id: "ord-1" };
      },
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    fireEvent.input(screen.getByLabelText("Limit net price"), { target: { value: "2.5" } });
    fireEvent.input(screen.getByLabelText("Limit amount"), { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: /place limit order/i }));
    await flush();

    // The ambiguous outcome is explicit — never a silent failure.
    expect(screen.getByTestId("limit-unknown")).toBeTruthy();
    expect(screen.getByText(/outcome unknown/i)).toBeTruthy();

    // Discard is two-step: the acknowledgement must be armed.
    const discard = screen.getByRole("button", {
      name: /discard unknown and continue/i,
    }) as HTMLButtonElement;
    expect(discard.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/verified the earlier limit order/i));
    await flush();
    expect(discard.disabled).toBe(false);

    // Retrying the same request is idempotent and reuses the key.
    mode = "ok";
    fireEvent.click(screen.getByRole("button", { name: /retry same order/i }));
    await flush();
    expect(screen.queryByTestId("limit-unknown")).toBeNull();
    const keys = client.calls
      .filter((call) => call.op === "place_limit_order")
      .map((call) => call.options?.idempotencyKey);
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);
  });

  it("keeps the UNKNOWN guard when a retry is rejected determinately", async () => {
    let mode: "network" | "auth" = "network";
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [] }),
      place_limit_order: () => {
        throw workspaceError(mode, mode === "network" ? "offline" : "unauthorized");
      },
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByLabelText("Limit net price"), { target: { value: "2.5" } });
    fireEvent.input(screen.getByLabelText("Limit amount"), { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: /place limit order/i }));
    await flush();
    expect(screen.getByTestId("limit-unknown")).toBeTruthy();

    // An auth rejection on a retry of the SAME unresolved request must not
    // release the guard or rotate the key: a gateway can reject before the
    // idempotency store is consulted, so it proves nothing about the first try.
    mode = "auth";
    const before = client.calls
      .filter((call) => call.op === "place_limit_order")
      .map((call) => call.options?.idempotencyKey);
    fireEvent.click(screen.getByRole("button", { name: /retry same order/i }));
    await flush();
    expect(screen.getByTestId("limit-unknown")).toBeTruthy();
    const after = client.calls
      .filter((call) => call.op === "place_limit_order")
      .map((call) => call.options?.idempotencyKey);
    expect(after.at(-1)).toBe(before[0]);
  });

  it("keeps the UNKNOWN guard when a 2xx place response carries no order id", async () => {
    // A success status is not proof of a placed order; a malformed/empty 2xx
    // must not release the guard (the write may still have committed).
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [] }),
      place_limit_order: () => null,
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByLabelText("Limit net price"), { target: { value: "2.5" } });
    fireEvent.input(screen.getByLabelText("Limit amount"), { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: /place limit order/i }));
    await flush();
    expect(screen.getByTestId("limit-unknown")).toBeTruthy();
  });

  it("refuses to place when a risk cap is non-empty but invalid", async () => {
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [] }),
      place_limit_order: () => ({ order_id: "ord-1" }),
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByLabelText("Limit net price"), { target: { value: "2.5" } });
    fireEvent.input(screen.getByLabelText("Limit amount"), { target: { value: "5" } });
    fireEvent.input(screen.getByLabelText("Max slippage bps"), { target: { value: "-1" } });
    const place = screen.getByRole("button", { name: /place limit order/i }) as HTMLButtonElement;
    expect(place.disabled).toBe(true);
    // Bypass the disabled attribute to exercise the action-time guard.
    place.disabled = false;
    fireEvent.click(place);
    await flush();
    expect(client.count("place_limit_order")).toBe(0);
    expect(screen.getByText(/Enter a non-negative max slippage/i)).toBeTruthy();
  });

  it("refuses a second concurrent place while the first is in flight", async () => {
    let release!: (value: unknown) => void;
    const pending = new Promise((resolve) => {
      release = resolve;
    });
    const client = new FakeCommandClient({
      get_orders: () => ({ orders: [] }),
      place_limit_order: async () => {
        await pending;
        return { order_id: "ord-1" };
      },
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByLabelText("Limit net price"), { target: { value: "2.5" } });
    fireEvent.input(screen.getByLabelText("Limit amount"), { target: { value: "5" } });
    const place = () =>
      screen.getByRole("button", { name: /place limit order/i }) as HTMLButtonElement;
    fireEvent.click(place());
    expect(place().disabled).toBe(true);
    // Solid suppresses delegated clicks on disabled nodes: force the control
    // enabled so the action-time `placing()` guard is what blocks the duplicate.
    place().disabled = false;
    fireEvent.click(place());
    place().disabled = false;
    fireEvent.click(place());
    await flush();
    expect(client.count("place_limit_order")).toBe(1);
    release(undefined);
    await flush();
    expect(client.count("place_limit_order")).toBe(1);
  });
});
