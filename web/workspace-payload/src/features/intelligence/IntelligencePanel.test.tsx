import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, waitFor } from "@solidjs/testing-library";
import type { ProviderHealth } from "../../contracts/market";
import { workspaceError } from "../../core/errors";
import { createWorkspaceStore, WorkspaceProvider, type WorkspaceStore } from "../../state/session";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import type { CommandClient, CommandSendOptions } from "../../transport/command";
import IntelligencePanel from "./IntelligencePanel";

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

const PROVIDERS: readonly ProviderHealth[] = [
  { provider: "gmgn", state: "healthy", reason: null, ageMs: 1_500 },
  { provider: "twitter", state: "degraded", reason: "Rate limited", ageMs: 45_000 },
  { provider: "okx", state: "circuit_open", reason: "5 consecutive failures", ageMs: 90_000 },
  { provider: "onchain", state: "unavailable", reason: null, ageMs: null },
];

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
      <IntelligencePanel />
    </WorkspaceProvider>
  ));
}

function healthClient(providers: readonly ProviderHealth[] = PROVIDERS): FakeCommandClient {
  return new FakeCommandClient({
    get_provider_health: () => ({ providers }),
  });
}

describe("IntelligencePanel", () => {
  afterEach(() => cleanup());

  it("loads provider health and renders state, reason and age", async () => {
    const client = healthClient();
    const store = await readyStore(client);
    renderPanel(store);

    await waitFor(() => expect(screen.getByText("gmgn")).toBeTruthy());
    expect(client.calls.filter((call) => call.op === "get_provider_health")).toHaveLength(1);
    expect(screen.getByText("healthy")).toBeTruthy();
    expect(screen.getByText("degraded")).toBeTruthy();
    expect(screen.getByText("circuit_open")).toBeTruthy();
    expect(screen.getByText("Rate limited")).toBeTruthy();
    expect(screen.getByText("5 consecutive failures")).toBeTruthy();
    expect(screen.getByText("45s")).toBeTruthy();
    expect(screen.getByText("1.5s")).toBeTruthy();
    // A null age is rendered as an explicit unknown, never fabricated.
    expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(2);
  });

  it("marks providers stale when telemetry exceeds the TTL", async () => {
    const client = healthClient();
    const store = await readyStore(client);
    renderPanel(store);

    await waitFor(() => expect(screen.getByText("gmgn")).toBeTruthy());
    // twitter (45s) and okx (90s) exceed the 30s TTL; gmgn (1.5s) does not.
    expect(screen.getAllByText("STALE")).toHaveLength(2);
    expect(document.querySelectorAll('.provider-table tr[data-stale="true"]').length).toBe(2);
  });

  it("renders the unavailable state when the command rejects with capability_missing", async () => {
    const client = new FakeCommandClient();
    const store = await readyStore(client);
    renderPanel(store);

    await waitFor(() => expect(screen.getByText("Not available on this deployment")).toBeTruthy());
  });

  it("surfaces a retryable command error", async () => {
    const client = new FakeCommandClient({
      get_provider_health: () => {
        throw workspaceError("server", "Provider broker failed.", { retryable: true });
      },
    });
    const store = await readyStore(client);
    renderPanel(store);

    await waitFor(() => expect(screen.getByText(/provider broker failed/i)).toBeTruthy());
    expect(screen.getByRole("button", { name: /retry/i })).toBeTruthy();
  });

  it("renders an empty state when no providers are reported", async () => {
    const client = healthClient([]);
    const store = await readyStore(client);
    renderPanel(store);

    await waitFor(() => expect(screen.getByText(/no provider telemetry/i)).toBeTruthy());
    expect(document.querySelector(".provider-table")).toBeNull();
  });
});
