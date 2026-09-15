import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import type { TokenDetail, TokenRef } from "../../contracts/market";
import { workspaceError } from "../../core/errors";
import { createWorkspaceStore, WorkspaceProvider, type WorkspaceStore } from "../../state/session";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import type { CommandClient, CommandSendOptions } from "../../transport/command";
import DiscoverPanel from "./DiscoverPanel";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

interface RecordedCall {
  readonly op: string;
  readonly payload: unknown;
}

class FakeCommandClient implements CommandClient {
  readonly calls: RecordedCall[] = [];

  constructor(
    private readonly handlers: Readonly<Record<string, (payload: unknown) => unknown>> = {},
  ) {}

  async send<T>(op: string, payload: unknown, _options?: CommandSendOptions): Promise<T> {
    this.calls.push({ op, payload });
    const handler = this.handlers[op];
    if (!handler) {
      // Mirrors UnavailableCommandClient: a missing contract fails closed.
      throw workspaceError("capability_missing", `No handler for "${op}".`);
    }
    return (await handler(payload)) as T;
  }
}

const TOKEN_REF: TokenRef = {
  chain: "base",
  address: "0x1234567890abcdef1234567890abcdef12345678",
  symbol: "PEPE",
  name: "Pepe",
};

const TOKEN_DETAIL: TokenDetail = {
  token: TOKEN_REF,
  stats: {
    priceUsd: 0.00042,
    priceChange24h: 0.1234,
    marketCapUsd: 42_000_000,
    liquidityUsd: 1_200_000,
    volume24hUsd: 3_400_000,
    holders: 12_345,
  },
  risk: {
    score: 72,
    factors: [
      {
        id: "honeypot",
        label: "Honeypot risk",
        severity: "high",
        detail: "Sell simulation reverted.",
      },
    ],
    buyTaxBps: 300,
    sellTaxBps: 500,
    transferFeeBps: 0,
    sellRestricted: true,
    simulated: true,
  },
  evidence: [
    {
      provider: "gmgn",
      kind: "liquidity",
      summary: "LP locked for 12 months",
      ageMs: 4_000,
      confidence: 0.9,
      stale: false,
    },
    {
      provider: "twitter",
      kind: "social",
      summary: "Mentions spiking",
      ageMs: 120_000,
      confidence: 0.4,
      stale: false,
    },
    {
      provider: "okx",
      kind: "onchain",
      summary: "Provider flagged the answer stale",
      ageMs: 1_000,
      confidence: null,
      stale: true,
    },
  ],
  slot: 12_345,
  sourceAgeMs: 1_200,
};

async function readyStore(command: CommandClient): Promise<WorkspaceStore> {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { intelligence: true, market: true },
      trading_enabled: false,
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

function renderPanel(store: WorkspaceStore) {
  return render(() => (
    <WorkspaceProvider store={store}>
      <DiscoverPanel />
    </WorkspaceProvider>
  ));
}

function searchInput(): HTMLInputElement {
  return screen.getByLabelText(/search token/i) as HTMLInputElement;
}

async function searchAndSelect(client: FakeCommandClient): Promise<void> {
  fireEvent.input(searchInput(), { target: { value: "PEPE" } });
  await waitFor(() => expect(client.calls.some((call) => call.op === "search_token")).toBe(true), {
    timeout: 1_000,
  });
  fireEvent.click(await screen.findByRole("button", { name: /PEPE/ }));
  await waitFor(() => expect(client.calls.some((call) => call.op === "get_token")).toBe(true));
}

function detailClient(): FakeCommandClient {
  return new FakeCommandClient({
    search_token: () => ({ results: [TOKEN_REF] }),
    get_token: () => TOKEN_DETAIL,
  });
}

describe("DiscoverPanel", () => {
  afterEach(() => cleanup());

  it("runs a debounced search and renders token stats and evidence", async () => {
    const client = detailClient();
    const store = await readyStore(client);
    renderPanel(store);

    fireEvent.input(searchInput(), { target: { value: "PEPE" } });
    await waitFor(() => expect(client.calls.some((call) => call.op === "search_token")).toBe(true), {
      timeout: 1_000,
    });
    expect(client.calls.find((call) => call.op === "search_token")?.payload).toEqual({
      query: "PEPE",
    });

    fireEvent.click(await screen.findByRole("button", { name: /PEPE/ }));
    await waitFor(() => expect(client.calls.some((call) => call.op === "get_token")).toBe(true));

    await waitFor(() => expect(screen.getByText("$42.00M")).toBeTruthy());
    expect(client.calls.find((call) => call.op === "get_token")?.payload).toEqual({
      chain: "base",
      address: TOKEN_REF.address,
    });
    expect(screen.getByText("$0.000420")).toBeTruthy();
    expect(screen.getByText("12.34%")).toBeTruthy();
    expect(screen.getByText("300 bps")).toBeTruthy();
    expect(screen.getByText("500 bps")).toBeTruthy();
    expect(screen.getByText(/honeypot risk/i)).toBeTruthy();
    expect(screen.getByText("Sell simulation reverted.")).toBeTruthy();
    expect(screen.getByText("LP locked for 12 months")).toBeTruthy();
    expect(screen.getByText("Mentions spiking")).toBeTruthy();
  });

  it("publishes the selected token to the shared instrument selection", async () => {
    const client = detailClient();
    const store = await readyStore(client);
    // Nothing is selected until the user picks a result.
    expect(store.selectedInstrument()).toBeNull();
    renderPanel(store);

    await searchAndSelect(client);

    // The detail load must be unaffected and the shared target set.
    expect(client.calls.some((call) => call.op === "get_token")).toBe(true);
    expect(store.selectedInstrument()).toEqual({
      chain: TOKEN_REF.chain,
      address: TOKEN_REF.address,
      symbol: "PEPE",
    });
  });

  it("marks evidence stale when flagged or when it exceeds its TTL", async () => {
    const client = detailClient();
    const store = await readyStore(client);
    renderPanel(store);
    await searchAndSelect(client);

    await waitFor(() => expect(screen.getByText("LP locked for 12 months")).toBeTruthy());
    // One item flagged stale + one beyond the 30s evidence TTL.
    await waitFor(() => expect(screen.getAllByText("STALE").length).toBeGreaterThanOrEqual(2));
    expect(document.querySelectorAll('.evidence-item[data-stale="true"]').length).toBe(2);
  });

  it("renders the unavailable state when the command rejects with capability_missing", async () => {
    const client = new FakeCommandClient();
    const store = await readyStore(client);
    renderPanel(store);

    fireEvent.input(searchInput(), { target: { value: "PEPE" } });
    await waitFor(
      () => expect(screen.getByText(/backend capability missing/i)).toBeTruthy(),
      { timeout: 1_000 },
    );
  });

  it("surfaces a retryable command error", async () => {
    const client = new FakeCommandClient({
      search_token: () => {
        throw workspaceError("server", "Upstream search failed.", { retryable: true });
      },
    });
    const store = await readyStore(client);
    renderPanel(store);

    fireEvent.input(searchInput(), { target: { value: "PEPE" } });
    await waitFor(() => expect(screen.getByText(/upstream search failed/i)).toBeTruthy(), {
      timeout: 1_000,
    });
    expect(screen.getByRole("button", { name: /retry/i })).toBeTruthy();
  });

  it("does not call the backend for an empty or whitespace-only query", async () => {
    const client = detailClient();
    const store = await readyStore(client);
    renderPanel(store);

    const input = searchInput();
    fireEvent.submit(input.closest("form") as HTMLFormElement);
    await flush();

    fireEvent.input(input, { target: { value: "   " } });
    fireEvent.submit(input.closest("form") as HTMLFormElement);
    await flush();

    expect(client.calls).toHaveLength(0);
  });

  it("collapses rapid typing into a single debounced search", async () => {
    const client = detailClient();
    const store = await readyStore(client);
    renderPanel(store);

    const input = searchInput();
    fireEvent.input(input, { target: { value: "P" } });
    fireEvent.input(input, { target: { value: "PE" } });
    fireEvent.input(input, { target: { value: "PEPE" } });

    await waitFor(() => expect(client.calls.length).toBeGreaterThan(0), { timeout: 1_000 });
    expect(client.calls.filter((call) => call.op === "search_token")).toHaveLength(1);
    expect(client.calls[0]?.payload).toEqual({ query: "PEPE" });
  });
});
