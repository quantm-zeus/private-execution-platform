import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { SecurityPanel } from "./SecurityPanel";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import type { CommandClient } from "../../transport/command";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function storeWith(command: CommandClient, tradingEnabled: boolean) {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { withdraw: true, market: true },
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

const recordingClient = (ops: string[]): CommandClient => ({
  async send<T>(op: string): Promise<T> {
    ops.push(op);
    return { request_id: "wr-1" } as unknown as T;
  },
});

describe("SecurityPanel", () => {
  afterEach(() => cleanup());

  it("fails the withdrawal surface closed while trading is disabled", async () => {
    const store = storeWith(recordingClient([]), false);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    const review = screen.getByRole("button", { name: /review withdrawal/i });
    expect((review as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getAllByText(/Trading is disabled by the global kill switch/i).length).toBeGreaterThan(0);
  });

  it("requires the exact confirmation phrase before submitting", async () => {
    const ops: string[] = [];
    const store = storeWith(recordingClient(ops), true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("Destination address"), {
      target: { value: "0x1234567890abcdef" },
    });
    fireEvent.input(screen.getByLabelText("Withdrawal amount"), { target: { value: "1.5" } });
    fireEvent.click(screen.getByRole("button", { name: /review withdrawal/i }));
    await flush();
    expect(screen.getByText("Destination")).toBeTruthy();

    const submit = screen.getByRole("button", { name: /request withdrawal/i });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(screen.getByLabelText("Withdrawal confirmation phrase"), {
      target: { value: "confirm withdrawal" },
    });
    expect((screen.getByRole("button", { name: /request withdrawal/i }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(screen.getByLabelText("Withdrawal confirmation phrase"), {
      target: { value: "CONFIRM WITHDRAWAL" },
    });
    fireEvent.click(screen.getByRole("button", { name: /request withdrawal/i }));
    await flush();
    expect(ops).toContain("request_withdrawal");
  });

  it("shows the kill-switch state and states that no signing surface exists", async () => {
    const store = storeWith(recordingClient([]), true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    expect(screen.getByText(/no generic signing/i)).toBeTruthy();
  });
});
