import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { TokenSearch } from "./TokenSearch";
import { WorkspaceProvider, createWorkspaceStore, type WorkspaceStore } from "../../state/session";
import { WorkstationProvider } from "../../state/workstation";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import type { CommandClient } from "../../transport/command";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const BONK = {
  chain: "base",
  address: "0xBONK000000000000000000000000000000000001",
  symbol: "BONK",
  name: "Bonk Inu",
  priceUsd: 0.0000123,
  marketCapUsd: 1_000_000,
  rank: 12,
};
const FULL = {
  chain: "solana",
  address: "FullAddress1111111111111111111111111111111",
  symbol: "FULL",
  name: "Full Token",
};

interface SearchCall {
  readonly query: string;
}

function createStore(): { store: WorkspaceStore; searches: SearchCall[] } {
  const searches: SearchCall[] = [];
  const command: CommandClient = {
    async send<T>(op: string, payload?: unknown): Promise<T> {
      if (op === "search_token") {
        const query = String((payload as { query?: unknown })?.query ?? "");
        searches.push({ query });
        // The mock provider matches symbol, name and full address, exactly like
        // the live FOMO bridge; the web layer must not rewrite the query.
        const results = query.toLowerCase().includes("bonk")
          ? [BONK]
          : query.toLowerCase().includes("fulladdress")
            ? [FULL]
            : [];
        return { results } as unknown as T;
      }
      return { accepted: true } as unknown as T;
    },
  };
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { realtime: true, market: true },
      trading_enabled: false,
      kill_switch: { enabled: false, reason: null },
      chains: [],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.setCommand(command);
  store.reload();
  return { store, searches };
}

function renderSearch(store: WorkspaceStore) {
  return render(() => (
    <WorkspaceProvider store={store}>
      <WorkstationProvider ws={store}>
        <TokenSearch />
      </WorkstationProvider>
    </WorkspaceProvider>
  ));
}

describe("TokenSearch", () => {
  afterEach(() => cleanup());

  it("dispatches the exact name query and renders symbol, name, chain, address and price", async () => {
    const { store, searches } = createStore();
    renderSearch(store);
    await flush();

    const input = screen.getByLabelText("Search token");
    fireEvent.input(input, { target: { value: "Bonk Inu" } });

    await waitFor(() => expect(searches).toHaveLength(1), { timeout: 2_000 });
    expect(searches[0]!.query).toBe("Bonk Inu");

    const option = await screen.findByRole("option");
    expect(option.textContent).toContain("BONK");
    expect(option.textContent).toContain("Bonk Inu");
    expect(option.textContent).toContain("base");
    expect(option.textContent).toContain("$0.000012");
  });

  it("dispatches the exact full-address query and renders the compact address", async () => {
    const { store, searches } = createStore();
    renderSearch(store);
    await flush();

    const input = screen.getByLabelText("Search token");
    fireEvent.input(input, { target: { value: FULL.address } });

    await waitFor(() => expect(searches).toHaveLength(1), { timeout: 2_000 });
    expect(searches[0]!.query).toBe(FULL.address);

    const option = await screen.findByRole("option");
    expect(option.textContent).toContain("FULL");
    expect(option.textContent).toContain("solana");
    // The full address is not dumped into the row; a compact form is shown.
    expect(option.textContent).not.toContain(FULL.address);
    // A missing price is an explicit unknown, never the address or a zero.
    expect(option.textContent).toContain("—");
  });

  it("selects the active option with the keyboard without altering the query", async () => {
    const { store, searches } = createStore();
    renderSearch(store);
    await flush();

    const input = screen.getByLabelText("Search token") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "bonk" } });
    await waitFor(() => expect(searches).toHaveLength(1), { timeout: 2_000 });
    await screen.findByRole("option");

    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "Enter" });
    await flush();

    expect(store.selectedInstrument()?.address).toBe(BONK.address);
    expect(searches).toHaveLength(1);
  });
});
