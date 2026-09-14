import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { ExecutionPanel } from "./ExecutionPanel";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import type { CommandClient } from "../../transport/command";
import type { RfqView } from "../../contracts/execution";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const rfq: RfqView = {
  rfqId: "rfq-1",
  state: "running",
  bestSolver: "solver-b",
  legs: [
    { solver: "solver-a", amountOut: "100", netOutput: 98, latencyMs: 40, viable: true },
    { solver: "solver-b", amountOut: "101", netOutput: 99.5, latencyMs: 55, viable: true },
    { solver: "solver-c", amountOut: "90", netOutput: 80, latencyMs: null, viable: false },
  ],
};

function storeWith(command: CommandClient, tradingEnabled: boolean) {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { twap: true, rfq: true, market: true },
      trading_enabled: tradingEnabled,
      kill_switch: { enabled: false, reason: null },
      chains: [{ id: "base", display: "Base", enabled: true }],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.reload();
  return store;
}

describe("ExecutionPanel", () => {
  afterEach(() => cleanup());

  it("fails TWAP and RFQ closed while trading is disabled", async () => {
    const store = storeWith({ async send<T>(): Promise<T> { throw new Error("unused"); } }, false);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));
    expect((screen.getByRole("button", { name: /start adaptive twap/i }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: /request quotes/i }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("renders solver legs with a BEST badge when quotes are available", async () => {
    const client: CommandClient = {
      async send<T>(): Promise<T> {
        return rfq as unknown as T;
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));
    fireEvent.click(screen.getByRole("button", { name: /request quotes/i }));
    await flush();
    expect(screen.getByText("BEST")).toBeTruthy();
    expect(screen.getAllByText("solver-b").length).toBeGreaterThan(0);
  });
});
