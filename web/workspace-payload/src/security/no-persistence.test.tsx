import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { AppShell } from "../app/AppShell";
import { WorkspaceProvider, createWorkspaceStore } from "../state/session";
import { parseWorkspaceSession } from "../transport/bootstrap";
import type { CommandClient } from "../transport/command";
import type { TokenDetail } from "../contracts/market";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const BONK = { chain: "base", address: "0xBONK", symbol: "BONK" } as const;

function bonkDetail(): TokenDetail {
  return {
    token: BONK,
    stats: {
      priceUsd: 0.0000123,
      priceChange24h: 5.5,
      marketCapUsd: 1_000_000,
      liquidityUsd: 250_000,
      volume24hUsd: 500_000,
      holders: 12_000,
    },
    risk: {
      score: 12,
      factors: [],
      buyTaxBps: 0,
      sellTaxBps: 50,
      transferFeeBps: 0,
      sellRestricted: false,
      simulated: true,
    },
    evidence: [],
    slot: 42,
    sourceAgeMs: 0,
  };
}

const WALLET_LIMITS = {
  wallet_ref: "0xwallet",
  max_trade_usd: 5_000,
  hourly_turnover_usd: 20_000,
  daily_turnover_usd: 100_000,
  max_buy_tax_bps: 500,
  max_sell_tax_bps: 400,
  max_price_impact_bps: 150,
  max_slippage_bps: 100,
  allowed_chains: ["base"],
  allowed_routers: ["okx"],
  allowed_programs: ["0xrouter"],
  source_age_ms: 1_200,
  slot: 7,
};

/**
 * In-memory encrypted command double: the workstation surfaces read through the
 * store's command channel, so the security test can mount the full workspace
 * without a backend while every read resolves to a truthful shape.
 */
function fakeCommandClient(): CommandClient {
  return {
    async send<T>(op: string): Promise<T> {
      switch (op) {
        case "search_token":
          return { results: [BONK] } as unknown as T;
        case "get_token":
          return bonkDetail() as unknown as T;
        case "get_orders":
          return { orders: [] } as unknown as T;
        case "get_portfolio":
          return {
            walletRef: "0xwallet",
            balances: [],
            equityUsd: 0,
            slot: 5,
            sourceAgeMs: 0,
          } as unknown as T;
        case "get_alerts":
          return { alerts: [] } as unknown as T;
        case "get_execution_progress":
          return {
            executionId: "ex-0",
            kind: "twap",
            state: "completed",
            chunksTotal: 1,
            chunksDone: 1,
            filledAmount: "100",
            remainingAmount: "0",
            realizedVsEstimateBps: 0,
            haltReason: null,
          } as unknown as T;
        case "get_wallet_limits":
          return WALLET_LIMITS as unknown as T;
        case "set_realtime_target":
          return { accepted: true } as unknown as T;
        default:
          throw new Error(`unexpected op ${op}`);
      }
    },
  };
}

/** A fully-capable in-memory session so every workstation surface can mount. */
function createRenderableStore() {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: {
        market: true,
        realtime: true,
        preview: true,
        execute: true,
        limits: true,
        portfolio: true,
        intelligence: true,
        withdraw: true,
        twap: true,
        rfq: true,
        okx: true,
        wallet_limits: true,
      },
      trading_enabled: true,
      kill_switch: { enabled: false, reason: null },
      chains: [{ id: "base", display: "Base", enabled: true, native_token: "USDC" }],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.setCommand(fakeCommandClient());
  store.reload();
  return store;
}

function renderShell(store: ReturnType<typeof createWorkspaceStore>) {
  render(() => (
    <WorkspaceProvider store={store}>
      <AppShell />
    </WorkspaceProvider>
  ));
}

/** Drive the header debounce and wait for the search popover (and rail rows). */
async function runTokenSearch(query: string) {
  const input = screen.getByLabelText("Search token") as HTMLInputElement;
  fireEvent.input(input, { target: { value: query } });
  await waitFor(
    () => expect(document.querySelector('.search-popover [role="option"]')).not.toBeNull(),
    { timeout: 2_000 },
  );
}

/**
 * Runtime proof that exercising every private workstation surface writes nothing
 * to persistent browser storage. The static scan in verify-web-boundary covers
 * the source; this covers the rendered application.
 */
describe("no plaintext persistence", () => {
  afterEach(() => {
    cleanup();
    localStorage.clear();
    sessionStorage.clear();
  });

  it("writes no private state to localStorage/sessionStorage/cookies across the workstation", async () => {
    const store = createRenderableStore();
    await flush();
    renderShell(store);
    await flush();

    // Market rail: run the header search, then select the token from the rail.
    await runTokenSearch("BONK");
    const railItem = document.querySelector<HTMLButtonElement>(".market-item");
    expect(railItem).not.toBeNull();
    fireEvent.click(railItem!);
    await flush();

    // Both ticket tabs.
    fireEvent.click(screen.getByTestId("ticket-tab-limit"));
    await flush();
    fireEvent.click(screen.getByTestId("ticket-tab-market"));
    await flush();

    // Every bottom dock surface.
    for (const id of ["positions", "orders", "activity", "trades", "holders"]) {
      fireEvent.click(screen.getByTestId(`dock-tab-${id}`));
      await flush();
    }

    // Security drawer (security + wallet-limits surfaces).
    fireEvent.click(screen.getByRole("button", { name: "Security and settings" }));
    await flush();
    expect(screen.getByRole("dialog", { name: "Security and settings" })).toBeTruthy();
    fireEvent.input(screen.getByLabelText("Withdrawal amount"), { target: { value: "10" } });
    await flush();
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await flush();

    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).toBe("");
    // Mounting and exercising the whole workstation is legitimately slow under
    // jsdom; the default 5s cap made this security test intermittently red.
  }, 20_000);

  /**
   * AC-W13.8: the OKX / Local Router preference is private trading intent, so
   * changing it must not touch storage, the URL, the document title or the
   * history stack (no trading semantics in URL/title/favicon/OG).
   */
  it("keeps the W13 router preference memory-only and out of URL/title/history", async () => {
    const store = createRenderableStore();
    await flush();
    renderShell(store);
    await flush();

    // Select a token so the market ticket (with its routing controls) renders.
    store.setSelectedInstrument({ chain: "base", address: "0xBONK", symbol: "BONK" });
    await flush();

    const urlBefore = location.href;
    const titleBefore = document.title;
    const historyBefore = history.length;

    const okx = screen.getByRole("button", { name: "OKX" });
    const local = screen.getByRole("button", { name: "Local Router" });
    expect(okx.getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(local);
    await flush();

    // The in-memory signal really changed...
    expect(store.routerPreference()).toBe("local");
    expect(local.getAttribute("aria-pressed")).toBe("true");
    // ...while nothing private was persisted or reflected into navigable state.
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).toBe("");
    expect(location.href).toBe(urlBefore);
    expect(document.title).toBe(titleBefore);
    expect(history.length).toBe(historyBefore);
  }, 20_000);
});
