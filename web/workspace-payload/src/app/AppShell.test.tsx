import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { AppShell } from "./AppShell";
import { WorkspaceProvider, createWorkspaceStore } from "../state/session";
import { parseWorkspaceSession } from "../transport/bootstrap";
import type { CommandClient } from "../transport/command";
import type { TokenDetail } from "../contracts/market";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const BONK = { chain: "base", address: "0xBONK", symbol: "BONK" } as const;
const PEPE = { chain: "base", address: "0xPEPE", symbol: "PEPE" } as const;

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

function pepeDetail(): TokenDetail {
  return {
    ...bonkDetail(),
    token: PEPE,
    stats: {
      ...bonkDetail().stats!,
      priceUsd: 2.5,
      priceChange24h: -3.25,
    },
    risk: {
      ...bonkDetail().risk!,
      score: 88,
      sellRestricted: true,
    },
    slot: 43,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
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
 * Deterministic command double. The workstation reads token search/detail,
 * orders, portfolio, execution progress and wallet limits through the store's
 * encrypted command channel; every op resolves to a shape the surface can parse.
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
        default:
          throw new Error(`unexpected op ${op}`);
      }
    },
  };
}

function createStore(command: CommandClient = fakeCommandClient()) {
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
  store.setCommand(command);
  store.reload();
  return store;
}

function renderShell(store: ReturnType<typeof createWorkspaceStore>) {
  return render(() => (
    <WorkspaceProvider store={store}>
      <AppShell />
    </WorkspaceProvider>
  ));
}

/** Drive the debounced header search and click the matching result. */
async function selectViaSearch(query: string, expectedSymbol: string) {
  const input = screen.getByLabelText("Search token") as HTMLInputElement;
  fireEvent.input(input, { target: { value: query } });
  let result: HTMLButtonElement | undefined;
  await waitFor(
    () => {
      result = Array.from(document.querySelectorAll<HTMLButtonElement>(".search-popover button")).find(
        (button) => button.textContent?.includes(expectedSymbol),
      );
      expect(result).not.toBeUndefined();
    },
    { timeout: 2_000 },
  );
  fireEvent.click(result!);
  await flush();
}

async function selectBonkViaSearch() {
  await selectViaSearch("BONK", "BONK");
}

function switchingCommandClient(secondDetail: Promise<TokenDetail>): CommandClient {
  const fallback = fakeCommandClient();
  return {
    async send<T>(op: string, payload?: unknown, options?: Parameters<CommandClient["send"]>[2]): Promise<T> {
      if (op === "search_token") {
        const query = String((payload as { query?: unknown } | undefined)?.query ?? "").toUpperCase();
        return { results: query.includes("PEPE") ? [PEPE] : [BONK] } as unknown as T;
      }
      if (op === "get_token") {
        const address = (payload as { address?: unknown } | undefined)?.address;
        if (address === PEPE.address) return (await secondDetail) as T;
        if (address === BONK.address) return bonkDetail() as T;
      }
      return fallback.send<T>(op, payload, options);
    },
  };
}

describe("AppShell", () => {
  afterEach(() => cleanup());

  it("renders a single workspace header, one Lock action, search and the ticket/dock tabs", async () => {
    const store = createStore();
    await flush();
    renderShell(store);
    await flush();

    expect(
      screen.getByRole("heading", { name: "Evergreen Private Workspace" }),
    ).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Lock" })).toHaveLength(1);
    expect(screen.getByRole("searchbox", { name: "Search token" })).toBeTruthy();
    expect(document.querySelector(".terminal.workspace")).not.toBeNull();
    expect(document.getElementById("terminal-main")).not.toBeNull();

    // Exactly two primary ticket tabs; Market is selected by default.
    expect(document.querySelectorAll('[data-testid^="ticket-tab-"]')).toHaveLength(2);
    expect(screen.getByTestId("ticket-tab-market").getAttribute("aria-selected")).toBe("true");
    expect(screen.getByTestId("ticket-tab-limit").getAttribute("aria-selected")).toBe("false");

    // Every bottom-dock tab exists.
    for (const id of ["positions", "orders", "activity", "trades", "holders"]) {
      expect(screen.getByTestId(`dock-tab-${id}`)).toBeTruthy();
    }
  });

  it("switches between Market and Limit while preserving the selected instrument", async () => {
    const store = createStore();
    await flush();
    renderShell(store);
    await flush();

    await selectBonkViaSearch();
    expect(screen.getByTestId("selected-instrument").textContent).toMatch(/BONK/);

    fireEvent.click(screen.getByTestId("ticket-tab-limit"));
    await flush();

    expect(screen.getByTestId("ticket-tab-limit").getAttribute("aria-selected")).toBe("true");
    expect(screen.getByTestId("ticket-tab-market").getAttribute("aria-selected")).toBe("false");
    expect(screen.getByTestId("selected-instrument").textContent).toMatch(/BONK/);
    expect(screen.getByTestId("limit-target").textContent).toMatch(/BONK/);
    expect(screen.getByLabelText("Limit net price")).toBeTruthy();

    fireEvent.click(screen.getByTestId("ticket-tab-market"));
    await flush();

    expect(screen.getByTestId("ticket-tab-market").getAttribute("aria-selected")).toBe("true");
    expect(screen.getByTestId("ticket-tab-limit").getAttribute("aria-selected")).toBe("false");
    expect(screen.getByTestId("selected-instrument").textContent).toMatch(/BONK/);
    expect(screen.getByTestId("trade-target").textContent).toMatch(/BONK/);
  });

  it("renders the selected token stats and risk strip from the injected detail read", async () => {
    const store = createStore();
    await flush();
    renderShell(store);
    await flush();

    await selectBonkViaSearch();

    for (const id of [
      "token-stat-price",
      "token-stat-change",
      "token-stat-marketcap",
      "token-stat-liquidity",
      "token-stat-volume",
    ]) {
      const node = screen.getByTestId(id);
      expect(node.textContent).toBeTruthy();
      expect(node.textContent).not.toBe("—");
    }
    expect(screen.getByTestId("token-risk")).toBeTruthy();
  });

  it("never renders token A stats or risk beside token B while B detail is loading", async () => {
    const pending = deferred<TokenDetail>();
    const store = createStore(switchingCommandClient(pending.promise));
    await flush();
    renderShell(store);
    await flush();

    await selectBonkViaSearch();
    await waitFor(() => expect(screen.getByTestId("token-stat-price")).toBeTruthy());
    expect(screen.getByTestId("token-risk").textContent).toMatch(/risk 12/);

    await selectViaSearch("PEPE", "PEPE");
    expect(screen.getByTestId("selected-instrument").textContent).toMatch(/PEPE/);
    expect(screen.queryByTestId("token-stat-price")).toBeNull();
    expect(screen.queryByTestId("token-risk")).toBeNull();

    pending.resolve(pepeDetail());
    await waitFor(() => expect(screen.getByTestId("token-stat-price").textContent).toContain("2.5"));
    expect(screen.getByTestId("token-risk").textContent).toMatch(/risk 88/);
  });

  it("keeps token A stats and risk hidden if token B detail fails", async () => {
    const pending = deferred<TokenDetail>();
    const store = createStore(switchingCommandClient(pending.promise));
    await flush();
    renderShell(store);
    await flush();

    await selectBonkViaSearch();
    await waitFor(() => expect(screen.getByTestId("token-stat-price")).toBeTruthy());
    expect(screen.getByTestId("token-risk").textContent).toMatch(/risk 12/);

    await selectViaSearch("PEPE", "PEPE");
    expect(screen.getByTestId("selected-instrument").textContent).toMatch(/PEPE/);
    expect(screen.queryByTestId("token-stat-price")).toBeNull();
    expect(screen.queryByTestId("token-risk")).toBeNull();

    pending.reject(new Error("provider unavailable"));
    await flush();
    await waitFor(() => expect(screen.queryByTestId("token-stat-price")).toBeNull());
    expect(screen.queryByTestId("token-risk")).toBeNull();
  });

  it("opens and closes the security drawer", async () => {
    const store = createStore();
    await flush();
    renderShell(store);
    await flush();

    const open = screen.getByRole("button", { name: "Security and settings" });
    fireEvent.click(open);
    await flush();

    expect(screen.getByRole("dialog", { name: "Security and settings" })).toBeTruthy();
    expect(document.querySelector(".drawer-backdrop")).not.toBeNull();
    expect(screen.getByLabelText("Destination address")).toBeTruthy();
    expect(screen.getByLabelText("Withdrawal amount")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Review withdrawal" })).toBeTruthy();
    expect(screen.getByTestId("limit-maxTradeUsd")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await flush();
    expect(screen.queryByRole("dialog", { name: "Security and settings" })).toBeNull();

    fireEvent.click(open);
    await flush();
    expect(screen.getByRole("dialog", { name: "Security and settings" })).toBeTruthy();

    fireEvent.keyDown(document.body, { key: "Escape" });
    await flush();
    expect(screen.queryByRole("dialog", { name: "Security and settings" })).toBeNull();
  });
});
