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
  routerPreference: "okx",
  routerSource: { id: "okx", detail: null },
};

function sessionPayload(execute: boolean, tradingEnabled: boolean, okx = true, nativeToken: string | null = "USDC") {
  return {
    protocol_version: 1,
    // Trade mutations are capital-committing, so the session advertises the
    // authoritative realtime feed they require.
    capabilities: { preview: true, execute, market: true, okx, realtime: true },
    trading_enabled: tradingEnabled,
    kill_switch: { enabled: false, reason: null },
    chains: [
      {
        id: "base",
        display: "Base",
        enabled: true,
        ...(nativeToken === null ? {} : { native_token: nativeToken }),
      },
    ],
    session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
    server_time_ms: 1_699_999_000_000,
  };
}

function makeStore(
  command: CommandClient,
  execute = true,
  tradingEnabled = false,
  okx = true,
  target = true,
) {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command,
    session: parseWorkspaceSession(sessionPayload(execute, tradingEnabled, okx, target ? "USDC" : null)),
  });
  // These fixtures model a live authoritative session: after the injected
  // bootstrap settles, mark the connection live so mutation tests exercise the
  // trading path rather than the fail-closed offline gate. (The bootstrap
  // microtask is scheduled before this one, so it runs first.)
  const reload = store.reload.bind(store);
  (store as { reload: () => void }).reload = () => {
    reload();
    queueMicrotask(() => {
      store.setConnection({
        phase: "live",
        lastFrameAtMs: 1_000,
        attempt: 0,
        nextRetryAtMs: null,
        reason: null,
      });
      // Publish the Discover target so the pair resolves to native → selected.
      if (target) {
        store.setSelectedInstrument({ chain: "base", address: "SOL", symbol: "SOL" });
      }
    });
  };
  return store;
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

/**
 * W13 test double: echo the requested `router_preference` as the source actually
 * used, so a valid preview always matches its request. Executions are recorded
 * with their bound source.
 */
function sourceEchoClient(
  executions?: { key?: string; payload?: unknown }[],
): CommandClient {
  return {
    async send<T>(
      op: string,
      payload?: unknown,
      options?: { idempotencyKey?: string },
    ): Promise<T> {
      if (op === "preview_market_order") {
        const preference =
          (payload as { router_preference?: "okx" | "local" } | undefined)?.router_preference ?? "okx";
        return {
          ...quote,
          routerPreference: preference,
          routerSource: { id: preference, detail: null },
        } as unknown as T;
      }
      if (op === "execute_market_order") {
        executions?.push({ key: options?.idempotencyKey, payload });
        const source =
          (payload as { router_preference?: "okx" | "local" } | undefined)?.router_preference ??
          "okx";
        // The backend must echo the source it actually executed (BR-10): a
        // missing/mismatched echo is treated as UNKNOWN by the panel.
        return {
          execution_id: "exec-1",
          router_source: { id: source, detail: null },
        } as unknown as T;
      }
      throw new Error(`unexpected op ${op}`);
    },
  };
}

function renderPanel(store: ReturnType<typeof makeStore>): void {
  render(() => (
    <WorkspaceProvider store={store}>
      <TradePanel />
    </WorkspaceProvider>
  ));
}

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
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(screen.getByText("Simulated net output (execution truth)")).toBeTruthy();
    expect(screen.getByText(/96\.2/)).toBeTruthy();
    expect(screen.getByText("aerodrome")).toBeTruthy();
    expect(screen.getByText(/slot 123/)).toBeTruthy();
    // Every cost in the route score is rendered, not just the net output.
    expect(screen.getByText("Tax")).toBeTruthy();
    expect(screen.getByText("50 bps")).toBeTruthy();
    expect(screen.getByText("30 bps")).toBeTruthy(); // DEX / provider fee
    expect(screen.getByText("$0.42")).toBeTruthy(); // gas
    expect(screen.getByText("12 bps")).toBeTruthy(); // price impact
    expect(screen.getByText("20 bps")).toBeTruthy(); // expected slippage
    expect(screen.getByText("5 bps")).toBeTruthy(); // MEV risk
    expect(screen.getByText("1.00%")).toBeTruthy(); // failure probability
    expect(screen.getByText("95.0")).toBeTruthy(); // minimum received
  });

  it("resolves the pair from the Discover selection and the chain native token", async () => {
    const intents: { token_in?: unknown; token_out?: unknown }[] = [];
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown): Promise<T> {
        if (op !== "preview_market_order") throw new Error(`unexpected op ${op}`);
        intents.push((payload as { intent?: { token_in?: unknown; token_out?: unknown } }).intent ?? {});
        return quote as unknown as T;
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    // Buy: the chain's advertised quote token in, the selected instrument out.
    expect(intents[0]?.token_in).toBe("USDC");
    expect(intents[0]?.token_out).toBe("SOL");

    // Sell reverses the legs, still resolved from the same target.
    fireEvent.click(screen.getByRole("button", { name: "Sell" }));
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(intents[1]?.token_in).toBe("SOL");
    expect(intents[1]?.token_out).toBe("USDC");
  });

  it("fails closed with no target and never sends a null-token preview", async () => {
    let calls = 0;
    const client: CommandClient = {
      async send<T>(): Promise<T> {
        calls += 1;
        return quote as unknown as T;
      },
    };
    // No advertised quote token and no Discover selection.
    const store = makeStore(client, true, true, true, false);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    const preview = screen.getByRole("button", { name: "Review order" }) as HTMLButtonElement;
    expect(preview.disabled).toBe(true);
    expect(screen.getByText(/select a token in discover/i)).toBeTruthy();
    fireEvent.click(preview);
    await flush();
    expect(calls).toBe(0);
  });

  it("fails closed when the selected address is empty", async () => {
    let calls = 0;
    const client: CommandClient = {
      async send<T>(): Promise<T> {
        calls += 1;
        return quote as unknown as T;
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    // A malformed search result must not slip past the null-only gate.
    store.setSelectedInstrument({ chain: "base", address: "", symbol: "X" });
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    const preview = screen.getByRole("button", { name: "Review order" }) as HTMLButtonElement;
    expect(preview.disabled).toBe(true);
    fireEvent.click(preview);
    await flush();
    expect(calls).toBe(0);
  });

  it("invalidates a preview when the shared target changes", async () => {
    const store = makeStore(sourceEchoClient(), true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect((screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled).toBe(
      false,
    );

    // A new Discover target (different token) invalidates the executable quote:
    // the preview's bound pair no longer matches the resolved pair.
    store.setSelectedInstrument({ chain: "base", address: "WIF", symbol: "WIF" });
    await flush();
    expect((screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    expect(screen.getAllByText(/ticket changed since this preview/i).length).toBeGreaterThan(0);
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
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    const buy = screen.getByRole("button", { name: /execute buy/i });
    expect((buy as HTMLButtonElement).disabled).toBe(true);
    // The disabled state is explained exactly once, not by repeated warning
    // blocks, and review/quote stays usable.
    expect(screen.getAllByTestId("execution-disabled")).toHaveLength(1);
    expect(screen.getByText(/Execution is disabled on this deployment/i)).toBeTruthy();
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
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
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
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
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
    const preview = screen.getByRole("button", { name: "Review order" }) as HTMLButtonElement;
    expect(preview.disabled).toBe(true);
    // Bypass the disabled attribute to exercise the action-time guard in
    // runPreview (Solid's delegated handler ignores clicks on disabled nodes).
    preview.disabled = false;
    fireEvent.click(preview);
    await flush();
    expect(calls).toBe(0);
  });

  it("refuses to preview when a risk limit is non-empty but invalid", async () => {
    let calls = 0;
    const counting: CommandClient = {
      async send<T>(): Promise<T> {
        calls++;
        return quote as unknown as T;
      },
    };
    const store = makeStore(counting);
    store.reload();
    await flush();
    renderPanel(store);
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    // A typo must not silently drop the cap to "unlimited".
    fireEvent.input(screen.getByLabelText("Max slippage bps"), { target: { value: "abc" } });
    const preview = screen.getByRole("button", { name: "Review order" }) as HTMLButtonElement;
    expect(preview.disabled).toBe(true);
    // Bypass the disabled attribute to exercise the action-time guard in runPreview.
    preview.disabled = false;
    fireEvent.click(preview);
    await flush();
    expect(calls).toBe(0);
    expect(screen.getByText(/Max slippage must be a non-negative/i)).toBeTruthy();
  });

  it("describes the previewed intent and invalidates the confirmation on edit", async () => {
    let submitted: unknown = null;
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          submitted = payload;
          return {
            execution_id: "exec-1",
            router_source: { id: "okx", detail: null },
          } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    // Execute capability on, trading gate open so the confirm step is reachable.
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();

    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    // The confirmation must render the previewed intent (100 USD), not the form.
    expect(screen.getByText(/confirm market buy for 100 usd on base/i)).toBeTruthy();

    // Editing the ticket while confirming must drop the confirmation entirely,
    // so a stale dialog can never describe a different trade than the submit.
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "999" } });
    expect(screen.queryByText(/confirm market buy/i)).toBeNull();
    expect(screen.getByRole("button", { name: /execute buy/i })).toBeTruthy();
    expect(submitted).toBeNull();
  });

  it("moves focus into the execute confirmation and back to Execute on cancel", async () => {
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();

    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    await flush();

    const dialog = screen.getByRole("alertdialog", { name: "Confirm market execution" });
    // Focus lands inside the confirmation so keyboard/screen-reader users are
    // not dropped onto <body> when the Execute button unmounts.
    expect(document.activeElement).toBe(dialog);

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await flush();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: /execute buy/i }));
  });

  it("renders an unconfirmed submit as an explicit UNKNOWN outcome, never a plain failure", async () => {
    const keys: (string | undefined)[] = [];
    const client: CommandClient = {
      async send<T>(
        op: string,
        _payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          keys.push(options?.idempotencyKey);
          throw new WorkspaceError({
            code: "network",
            message: "Command transport failed.",
            retryable: true,
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();

    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    expect(screen.queryByText(/Submitted execution/i)).toBeNull();
    // The key is a client-generated idempotency key (not a raw backend quote id),
    // and a retry of the same submission reuses it so it cannot create a second
    // trade.
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^market-/);
    fireEvent.click(screen.getByRole("button", { name: /Retry same order/i }));
    await flush();
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);
  });

  it("surfaces the UNKNOWN discard escape when a write denial blocks the retry", async () => {
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          throw new WorkspaceError({
            code: "network",
            message: "Command transport failed.",
            retryable: true,
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    // While the mutation gate is open the idempotent retry is the path, so the
    // discard block stays hidden.
    expect(screen.queryByTestId("new-order-blocked")).toBeNull();

    // Once realtime freshness halts writes, the retry is no longer available; the
    // explicit two-step discard must become reachable instead of trapping the
    // user behind a disabled button and a possibly-committed order.
    store.setConnection({
      phase: "degraded",
      lastFrameAtMs: null,
      attempt: 0,
      nextRetryAtMs: null,
      reason: "stream down",
    });
    await flush();
    expect(screen.getByTestId("new-order-blocked")).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: /Retry same order/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it("renders a determinate backend rejection as an error, not UNKNOWN", async () => {
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          throw new WorkspaceError({
            code: "freshness",
            message: "Command rejected: state changed.",
            // Non-retryable: the backend proved no commit, so the write is
            // determinate and the idempotency key rotates.
            retryable: false,
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();

    expect(screen.getByText(/Command rejected: state changed/i)).toBeTruthy();
    expect(screen.queryByText(/Execution outcome unknown/i)).toBeNull();
  });

  it("treats a retryable freshness rejection as UNKNOWN (the write may have committed)", async () => {
    // A transient backend failure can be surfaced under a freshness code while
    // the order may still have reached the chain. Rotating the idempotency key
    // here would let the next submission create a duplicate, so the outcome must
    // stay indeterminate regardless of the code.
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          throw new WorkspaceError({
            code: "freshness",
            message: "Command backend is unavailable.",
            retryable: true,
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();

    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
  });

  it("keeps the UNKNOWN guard when a retry is rejected determinately", async () => {
    const keys: (string | undefined)[] = [];
    let mode: "network" | "freshness" = "network";
    const client: CommandClient = {
      async send<T>(
        op: string,
        _payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          keys.push(options?.idempotencyKey);
          throw new WorkspaceError({
            code: mode,
            message: mode === "network" ? "Command transport failed." : "state changed",
            retryable: mode === "network",
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();

    // A determinate rejection of the *retry* must not release the guard or reset
    // the preview: it does not prove the first attempt did not commit.
    mode = "freshness";
    fireEvent.click(screen.getByRole("button", { name: /Retry same order/i }));
    await flush();
    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);
  });

  it("refuses to execute a preview whose backend source age exceeds its TTL", async () => {
    const staleQuote: QuotePreview = { ...quote, sourceAgeMs: 120_000 };
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return staleQuote as unknown as T;
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();

    // The backend-provided source age must drive staleness, not a hardcoded 0.
    const buy = screen.getByRole("button", { name: /execute buy/i });
    expect((buy as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getAllByText(/stale/i).length).toBeGreaterThan(0);
  });

  it("fails closed at confirm time when the session deadline lapses after a fresh preview", async () => {
    // The session gate reads the raw clock, so a deadline that passes purely with
    // wall time must not leave Execute armed with a cached `null` denial. The
    // quote itself stays fresh (5s TTL) while the 2s session lapses.
    let now = 1_000;
    const executions: { key?: string; payload?: unknown }[] = [];
    const payload = sessionPayload(true, true);
    const store = createWorkspaceStore({
      manualClock: true,
      clock: () => now,
      command: sourceEchoClient(executions),
      session: parseWorkspaceSession({
        ...payload,
        session: { key_id: "kid-1", expires_at_ms: payload.server_time_ms + 2_000 },
      }),
    });
    const reload = store.reload.bind(store);
    (store as { reload: () => void }).reload = () => {
      reload();
      queueMicrotask(() => {
        store.setConnection({
          phase: "live",
          lastFrameAtMs: 1_000,
          attempt: 0,
          nextRetryAtMs: null,
          reason: null,
        });
        store.setSelectedInstrument({ chain: "base", address: "SOL", symbol: "SOL" });
      });
    };
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(
      (screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled,
    ).toBe(false);

    // Session deadline (bootstrap clock + 2s) has now passed; the previewed quote
    // has not expired. Confirmation must re-evaluate the gate and refuse.
    now = 3_500;
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();

    expect(executions).toHaveLength(0);
    expect(screen.getAllByText(/Session authorization has expired/i).length).toBeGreaterThan(0);
  });

  it("fails closed when the preview omits the required revalidation flag", async () => {
    // A relay that strips `revalidationRequired` must not turn a quote the
    // backend intended for revalidation into an executable one.
    const { revalidationRequired: _omitted, ...withoutFlag } = quote;
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return withoutFlag as unknown as T;
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(
      (screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(screen.getAllByText(/requires revalidation|revalidation before executing/i).length).toBeGreaterThan(0);
  });

  it("fails closed when the preview expiry is missing or malformed", async () => {
    const withoutExpiry = { ...quote, expiresAtMs: undefined };
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return withoutExpiry as unknown as T;
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(
      (screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(screen.getAllByText(/expiry was missing or malformed/i).length).toBeGreaterThan(0);
  });

  it("does not crash or enable execute when the preview omits its intent", async () => {
    const withoutIntent = { ...quote, intent: undefined };
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return withoutIntent as unknown as T;
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(
      (screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it("compares a server-issued preview expiry against the server-anchored clock", async () => {
    // The bootstrap anchor is unauthenticated and clamped to a bounded forward
    // skew (5 min), so serverNow ≈ local + 300_000 = 301_000 while the local
    // clock is 1_000. A deadline between the two must be expired on the server
    // clock even though a naive local comparison would not expire it.
    const expiredQuote: QuotePreview = { ...quote, expiresAtMs: 200_000 };
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return expiredQuote as unknown as T;
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(
      (screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(screen.getAllByText(/Preview expired/i).length).toBeGreaterThan(0);
  });

  it("does not re-submit an already-executed preview", async () => {
    let execCalls = 0;
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          execCalls++;
          return {
            execution_id: "exec-1",
            router_source: { id: "okx", detail: null },
          } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();

    expect(screen.getByText(/Submitted execution exec-1/)).toBeTruthy();
    expect(execCalls).toBe(1);
    // The completed preview must not be re-submitted with the same key.
    const buy = screen.getByRole("button", { name: /execute buy/i });
    expect((buy as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/already submitted/i)).toBeTruthy();
  });

  it("does not let an UNKNOWN outcome submit a different, freshly previewed quote", async () => {
    const keys: (string | undefined)[] = [];
    let previews = 0;
    const client: CommandClient = {
      async send<T>(
        op: string,
        payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "preview_market_order") {
          previews += 1;
          // Echo the requested amount like a real backend, so the preview binds
          // to the current ticket (the panel refuses to execute a stale preview).
          const requested = (payload as { intent?: { amount?: string } } | undefined)?.intent;
          return {
            ...quote,
            quoteId: previews === 1 ? "q-1" : "q-2",
            intent: { ...quote.intent, amount: requested?.amount ?? quote.intent.amount },
          } as unknown as T;
        }
        if (op === "execute_market_order") {
          keys.push(options?.idempotencyKey);
          throw new WorkspaceError({
            code: "network",
            message: "Command transport failed.",
            retryable: true,
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    expect(keys).toHaveLength(1);
    const firstKey = keys[0];

    // A new preview is a new logical order. While the earlier submission is
    // still UNKNOWN it must not be executable under a new idempotency key.
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "250" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();

    const retry = screen.getByRole("button", { name: /Retry same order/i });
    expect((retry as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId("new-order-blocked")).toBeTruthy();
    const buy = screen.getByRole("button", { name: /execute buy/i });
    expect((buy as HTMLButtonElement).disabled).toBe(true);
    expect(keys).toHaveLength(1);

    // The explicit two-step acknowledgement releases the block; the next submit
    // is the new quote under a *new* key (a genuinely new, user-confirmed order).
    fireEvent.click(screen.getByLabelText(/I verified the earlier order out-of-band/i));
    fireEvent.click(screen.getByRole("button", { name: /discard UNKNOWN and continue/i }));
    await flush();
    expect(screen.queryByText(/Execution outcome unknown/i)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(keys).toHaveLength(2);
    expect(keys[1]).not.toBe(firstKey);
  });

  it("keeps the executed-quote guard when a re-preview returns the same quote id", async () => {
    let execCalls = 0;
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        // The backend returns the same quote id for identical parameters.
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          execCalls++;
          return {
            execution_id: "exec-1",
            router_source: { id: "okx", detail: null },
          } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(execCalls).toBe(1);

    // Re-previewing does not drop the guard: the same quote id is still blocked.
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    const buy = screen.getByRole("button", { name: /execute buy/i });
    expect((buy as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/already submitted/i)).toBeTruthy();
    expect(execCalls).toBe(1);
  });

  it("blocks a second submit while the first is in flight", async () => {
    let resolveExec!: (value: { execution_id: string; router_source: { id: string; detail: null } }) => void;
    const pending = new Promise<{ execution_id: string; router_source: { id: string; detail: null } }>(
      (resolve) => {
        resolveExec = resolve;
      },
    );
    let execCalls = 0;
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          execCalls++;
          return pending as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();

    // While the submit is unresolved, neither Preview nor Execute may start a
    // second, racing submission that could erase a later UNKNOWN.
    expect((screen.getByRole("button", { name: "Review order" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled).toBe(true);

    resolveExec({ execution_id: "exec-1", router_source: { id: "okx", detail: null } });
    await flush();
    expect(execCalls).toBe(1);
    expect(screen.getByText(/Submitted execution exec-1/)).toBeTruthy();
  });

  it("refuses to execute a preview after the ticket amount is edited", async () => {
    const store = makeStore(quotingClient, true, true);
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <TradePanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect((screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled).toBe(
      false,
    );

    // Editing the ticket without re-previewing must invalidate the executable
    // preview: the $100 quote cannot execute a $10,000 order.
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "10000" } });
    expect((screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    expect(screen.getAllByText(/ticket changed since this preview/i).length).toBeGreaterThan(0);
  });

  // --- W13: OKX / Local Router source selector ---------------------------------

  it("defaults to OKX before any preview and sends router_preference=okx", async () => {
    const payloads: unknown[] = [];
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown): Promise<T> {
        if (op !== "preview_market_order") throw new Error(`unexpected op ${op}`);
        payloads.push(payload);
        return quote as unknown as T;
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    expect(
      screen.getByRole("button", { name: "OKX" }).getAttribute("aria-pressed"),
    ).toBe("true");
    expect(
      screen.getByRole("button", { name: "Local Router" }).getAttribute("aria-pressed"),
    ).toBe("false");

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();

    expect((payloads[0] as { router_preference?: string }).router_preference).toBe("okx");
    // The actual source used is rendered, not just the selection.
    expect(screen.getByText(/route source OKX/)).toBeTruthy();
  });

  it("sends router_preference=local after explicitly selecting Local Router", async () => {
    const payloads: unknown[] = [];
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown): Promise<T> {
        if (op !== "preview_market_order") throw new Error(`unexpected op ${op}`);
        payloads.push(payload);
        const preference =
          (payload as { router_preference?: "okx" | "local" } | undefined)?.router_preference ??
          "local";
        return {
          ...quote,
          routerPreference: preference,
          routerSource: { id: preference, detail: null },
        } as unknown as T;
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.click(screen.getByRole("button", { name: "Local Router" }));
    expect(
      screen.getByRole("button", { name: "Local Router" }).getAttribute("aria-pressed"),
    ).toBe("true");
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();

    expect((payloads[0] as { router_preference?: string }).router_preference).toBe("local");
    expect(screen.getByText(/route source Local Router/)).toBeTruthy();
  });

  it("invalidates the preview and execute state when the routing source changes", async () => {
    const store = makeStore(sourceEchoClient(), true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect((screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled).toBe(
      false,
    );

    // Switching source invalidates the source-bound preview and confirmation.
    fireEvent.click(screen.getByRole("button", { name: "Local Router" }));
    expect(screen.getByText(/No preview yet/)).toBeTruthy();
    expect((screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled).toBe(
      true,
    );

    // A fresh preview for the new source is required before executing again.
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect((screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled).toBe(
      false,
    );
    expect(screen.getByText(/route source Local Router/)).toBeTruthy();
  });

  it("refuses a silent fallback when OKX is requested but Local is used", async () => {
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op !== "preview_market_order") throw new Error(`unexpected op ${op}`);
        return {
          ...quote,
          routerPreference: "okx",
          routerSource: { id: "local", detail: null },
        } as unknown as T;
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();

    expect((screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    expect(screen.getAllByText(/silent fallback/i).length).toBeGreaterThan(0);
  });

  it("offers an explicit Local escape when OKX quoting fails, without auto-fallback", async () => {
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown): Promise<T> {
        if (op !== "preview_market_order") throw new Error(`unexpected op ${op}`);
        const preference =
          (payload as { router_preference?: "okx" | "local" } | undefined)?.router_preference ??
          "local";
        if (preference === "okx") {
          throw new WorkspaceError({
            code: "server",
            message: "OKX benchmark unavailable.",
            retryable: true,
          });
        }
        return {
          ...quote,
          routerPreference: preference,
          routerSource: { id: preference, detail: null },
        } as unknown as T;
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();

    expect(screen.getByTestId("okx-unavailable")).toBeTruthy();
    // No automatic fallback: OKX is still selected and no Local quote rendered.
    expect(screen.getByRole("button", { name: "OKX" }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.queryByText(/route source Local Router/)).toBeNull();

    // The user may explicitly choose Local, then requote.
    fireEvent.click(screen.getByRole("button", { name: "Use Local Router" }));
    expect(
      screen.getByRole("button", { name: "Local Router" }).getAttribute("aria-pressed"),
    ).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(screen.getByText(/route source Local Router/)).toBeTruthy();
  });

  it("keeps an indeterminate OKX submission guarded after switching to Local", async () => {
    const executions: { key?: string; payload?: unknown }[] = [];
    let previewCount = 0;
    const client: CommandClient = {
      async send<T>(
        op: string,
        payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "preview_market_order") {
          previewCount += 1;
          const preference =
            (payload as { router_preference?: "okx" | "local" } | undefined)?.router_preference ??
            "okx";
          return {
            ...quote,
            quoteId: `${preference}-q-${previewCount}`,
            routerPreference: preference,
            routerSource: { id: preference, detail: null },
          } as unknown as T;
        }
        if (op === "execute_market_order") {
          executions.push({ key: options?.idempotencyKey, payload });
          throw new WorkspaceError({
            code: "network",
            message: "Command transport failed.",
            retryable: true,
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    expect(executions).toHaveLength(1);
    expect((executions[0]!.payload as { router_preference?: string }).router_preference).toBe("okx");

    // Switching to Local must not clear the UNKNOWN or allow a new order.
    fireEvent.click(screen.getByRole("button", { name: "Local Router" }));
    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled,
    ).toBe(true);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "250" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(screen.getByTestId("new-order-blocked")).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: /Retry same order/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(executions).toHaveLength(1);
  });

  it("auto-selects an available Local route when OKX is not advertised", async () => {
    const payloads: unknown[] = [];
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown): Promise<T> {
        if (op !== "preview_market_order") throw new Error(`unexpected op ${op}`);
        payloads.push(payload);
        const preference =
          (payload as { router_preference?: "okx" | "local" } | undefined)?.router_preference ??
          "local";
        return {
          ...quote,
          routerPreference: preference,
          routerSource: { id: preference, detail: null },
        } as unknown as T;
      },
    };
    // `okx: false`: the backend does not advertise the OKX route.
    const store = makeStore(client, true, true, false);
    store.reload();
    await flush();
    renderPanel(store);
    await flush();

    // OKX cannot be selected, and the ticket binds to the available Local route
    // by default instead of leaving an unusable OKX selection in place.
    expect((screen.getByRole("button", { name: "OKX" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("button", { name: "OKX" }).getAttribute("aria-pressed")).toBe("false");
    expect(
      screen.getByRole("button", { name: "Local Router" }).getAttribute("aria-pressed"),
    ).toBe("true");

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    expect(
      (screen.getByRole("button", { name: "Review order" }) as HTMLButtonElement).disabled,
    ).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect((payloads[0] as { router_preference?: string }).router_preference).toBe("local");
  });

  it("keeps route choice and risk caps behind Advanced without weakening route binding", async () => {
    const payloads: unknown[] = [];
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown): Promise<T> {
        if (op !== "preview_market_order") throw new Error(`unexpected op ${op}`);
        payloads.push(payload);
        const preference =
          (payload as { router_preference?: "okx" | "local" } | undefined)?.router_preference ??
          "okx";
        return {
          ...quote,
          routerPreference: preference,
          routerSource: { id: preference, detail: null },
        } as unknown as T;
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);
    await flush();

    // Simple-by-default: the risk/route controls start collapsed, while the
    // bound route is still surfaced and remains authoritative.
    const advanced = screen.getByTestId("ticket-advanced") as HTMLDetailsElement;
    expect(advanced.open).toBe(false);
    expect(store.routerPreference()).toBe("okx");
    expect(screen.getByText(/Route OKX/)).toBeTruthy();

    // Expanding Advanced reveals the real route control and the risk caps; the
    // selection is bound exactly (never a silent fallback).
    advanced.open = true;
    fireEvent(advanced, new Event("toggle"));
    fireEvent.click(screen.getByRole("button", { name: "Local Router" }));
    expect(store.routerPreference()).toBe("local");
    fireEvent.input(screen.getByLabelText("Max slippage bps"), { target: { value: "55" } });
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();

    const sent = payloads[0] as {
      router_preference?: string;
      intent?: { max_slippage_bps?: number };
    };
    expect(sent.router_preference).toBe("local");
    expect(sent.intent?.max_slippage_bps).toBe(55);
  });

  it("shows the bound routing source on the confirmation and the submitted result", async () => {
    const store = makeStore(sourceEchoClient(), true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    expect(screen.getByText(/via OKX\. Execution cannot be undone/i)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Submitted execution exec-1 via OKX/i)).toBeTruthy();
  });

  it("keeps an UNKNOWN guard when the backend reuses one quote id across sources", async () => {
    const executions: { key?: string; payload?: unknown }[] = [];
    const client: CommandClient = {
      async send<T>(
        op: string,
        payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "preview_market_order") {
          // Adversarial backend: one quote id is reused for both sources, so only
          // the source can distinguish the orders. The guard must not rely on the
          // id alone.
          const preference =
            (payload as { router_preference?: "okx" | "local" } | undefined)?.router_preference ??
            "okx";
          return {
            ...quote,
            quoteId: "shared-q",
            routerPreference: preference,
            routerSource: { id: preference, detail: null },
          } as unknown as T;
        }
        if (op === "execute_market_order") {
          executions.push({ key: options?.idempotencyKey, payload });
          throw new WorkspaceError({
            code: "network",
            message: "Command transport failed.",
            retryable: true,
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    expect(executions).toHaveLength(1);

    // Same quote id, different source: the UNKNOWN is still for OKX, so a Local
    // preview must not re-enable a retry or a new execute.
    fireEvent.click(screen.getByRole("button", { name: "Local Router" }));
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(screen.getByTestId("new-order-blocked")).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: /Retry same order/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(
      (screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(executions).toHaveLength(1);
  });

  it("treats an execute response that echoes a different source as UNKNOWN, not success", async () => {
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          // The request was bound to OKX; a Local echo means the backend may have
          // re-routed, which is never a confident success.
          return {
            execution_id: "exec-1",
            router_source: { id: "local", detail: null },
          } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();

    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    expect(screen.queryByText(/Submitted execution/i)).toBeNull();
  });

  it("accepts a matching execute-source echo", async () => {
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          return {
            execution_id: "exec-1",
            router_source: { id: "okx", detail: null },
          } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Submitted execution exec-1 via OKX/i)).toBeTruthy();
  });

  it("treats an explicit null execute-source echo as UNKNOWN, not success", async () => {
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          // A serde `Option` without `skip_serializing_if` emits null on success;
          // the true route is unproven, so this must not render a confident claim.
          return { execution_id: "exec-1", router_source: null } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    expect(screen.queryByText(/Submitted execution/i)).toBeNull();
  });

  it("treats a missing execute-source echo as UNKNOWN, never an attributed success", async () => {
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "preview_market_order") return quote as unknown as T;
        if (op === "execute_market_order") {
          return { execution_id: "exec-1" } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    expect(screen.queryByText(/Submitted execution/i)).toBeNull();
  });

  it("blocks a same-quote-id preview of a different intent as a new order, not a retry", async () => {
    const executions: { key?: string; payload?: unknown }[] = [];
    const client: CommandClient = {
      async send<T>(
        op: string,
        payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "preview_market_order") {
          // Adversarial backend: one quote id reused for a *different* order
          // (different amount), which must not be mistaken for an idempotent retry.
          const requested = (payload as { intent?: { amount?: string } } | undefined)?.intent;
          return {
            ...quote,
            quoteId: "shared-q",
            intent: { ...quote.intent, amount: requested?.amount ?? quote.intent.amount },
          } as unknown as T;
        }
        if (op === "execute_market_order") {
          executions.push({ key: options?.idempotencyKey, payload });
          throw new WorkspaceError({
            code: "network",
            message: "Command transport failed.",
            retryable: true,
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Execution outcome unknown/i)).toBeTruthy();
    expect(executions).toHaveLength(1);

    // The backend returns the SAME quote id for a $250 order. The intent differs,
    // so this is a new order: Retry and Execute must both stay disabled.
    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "250" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    expect(screen.getByTestId("new-order-blocked")).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: /Retry same order/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(
      (screen.getByRole("button", { name: /execute buy/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(executions).toHaveLength(1);
  });

  it("binds the canonical P84B string router_source on preview and execute (W15)", async () => {
    const executions: { key?: string; payload?: unknown }[] = [];
    const client: CommandClient = {
      async send<T>(
        op: string,
        payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "preview_market_order") {
          // Canonical origin/main agent-backend shape: the bare wire label
          // (`MarketPreview.router_source` is a `RouterSource` string).
          return { ...quote, routerSource: "okx" } as unknown as T;
        }
        if (op === "execute_market_order") {
          executions.push({ key: options?.idempotencyKey, payload });
          return { execution_id: "exec-canonical", router_source: "okx" } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = makeStore(client, true, true);
    store.reload();
    await flush();
    renderPanel(store);

    fireEvent.input(screen.getByLabelText("Amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Review order" }));
    await flush();
    // A canonical string source is executable and rendered, not treated as a
    // missing/malformed source.
    expect(screen.getByText(/route source OKX/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /execute buy/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm execution" }));
    await flush();
    expect(screen.getByText(/Submitted execution exec-canonical via OKX/i)).toBeTruthy();
  });
});
