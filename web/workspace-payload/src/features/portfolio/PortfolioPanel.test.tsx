import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@solidjs/testing-library";
import { workspaceError } from "../../core/errors";
import type { CommandClient } from "../../transport/command";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import type { PortfolioView } from "../../contracts/execution";
import PortfolioPanel from "./PortfolioPanel";

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
}

async function readyStore(options: { command: CommandClient }) {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1000,
    command: options.command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { limits: true, portfolio: true, intelligence: true },
      trading_enabled: true,
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

function makePortfolio(overrides: Partial<PortfolioView> = {}): PortfolioView {
  return {
    walletRef: "0x9999999999999999999999999999999999999999",
    balances: [],
    equityUsd: 0,
    slot: 5,
    sourceAgeMs: 0,
    ...overrides,
  };
}

function renderPanel(store: ReturnType<typeof createWorkspaceStore>) {
  return render(() => (
    <WorkspaceProvider store={store}>
      <PortfolioPanel />
    </WorkspaceProvider>
  ));
}

describe("PortfolioPanel", () => {
  afterEach(() => cleanup());

  it("marks a balance past its TTL as stale, never fresh", async () => {
    const client = new FakeCommandClient({
      get_portfolio: () =>
        makePortfolio({
          balances: [
            {
              chain: "base",
              token: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              symbol: "USDC",
              amount: "100",
              usdValue: 100,
              ageMs: 45_000,
            },
          ],
        }),
      get_alerts: () => ({ alerts: [] }),
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    expect(screen.getByText("USDC")).toBeTruthy();
    expect(screen.getAllByText("STALE").length).toBeGreaterThan(0);
    const row = document.querySelector('tr[data-balance-token="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]');
    expect(row?.getAttribute("data-stale")).toBe("true");
    expect(screen.queryByText("FRESH")).toBeNull();
  });

  it("renders an em dash for a null usd value, never zero", async () => {
    const client = new FakeCommandClient({
      get_portfolio: () =>
        makePortfolio({
          equityUsd: null,
          balances: [
            {
              chain: "base",
              token: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              symbol: "MYST",
              amount: "10",
              usdValue: null,
              ageMs: 1_000,
            },
          ],
        }),
      get_alerts: () => ({ alerts: [] }),
    });
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    const usdCells = screen.getAllByTestId("balance-usd");
    expect(usdCells[0].textContent).toBe("—");
    expect(screen.queryByText("$0.00")).toBeNull();
  });

  it("renders the unavailable/error state when the client rejects", async () => {
    const client = new FakeCommandClient({});
    const store = await readyStore({ command: client });
    renderPanel(store);
    await flush();

    const alerts = screen.getAllByRole("alert");
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts[0].textContent).toMatch(/temporary failure|request failed|unavailable/i);
  });

  it("renders unavailable, not an unqueried 'No alerts', when intelligence is missing", async () => {
    const client = new FakeCommandClient({ get_portfolio: () => makePortfolio({}) });
    const store = createWorkspaceStore({
      manualClock: true,
      clock: () => 1000,
      command: client,
      session: parseWorkspaceSession({
        protocol_version: 1,
        capabilities: { portfolio: true }, // no intelligence
        trading_enabled: true,
        kill_switch: { enabled: false, reason: null },
        chains: [],
        session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
        server_time_ms: 1_699_999_000_000,
      }),
    });
    store.reload();
    await flush();
    renderPanel(store);
    await flush();

    // The alerts resource was never queried, so it must not claim "No alerts".
    expect(screen.queryByText("No alerts")).toBeNull();
    expect(screen.getByText(/Backend capability missing/i)).toBeTruthy();
    expect(client.calls.some((call) => call.op === "get_alerts")).toBe(false);
  });
});
