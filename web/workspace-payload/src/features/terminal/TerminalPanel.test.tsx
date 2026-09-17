import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@solidjs/testing-library";
import { TerminalPanel } from "./TerminalPanel";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import { WorkstationProvider } from "../../state/workstation";
import { parseWorkspaceSession } from "../../transport/bootstrap";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe("TerminalPanel", () => {
  afterEach(() => cleanup());

  it("renders the local chart surface and awaits the encrypted feed without inventing data", async () => {
    const store = createWorkspaceStore({
      manualClock: true,
      clock: () => 1_000,
      command: { async send<T>(): Promise<T> { throw new Error("unused"); } },
      session: parseWorkspaceSession({
        protocol_version: 1,
        capabilities: { realtime: true, market: true, chart: true },
        trading_enabled: false,
        kill_switch: { enabled: false, reason: null },
        chains: [],
        session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
        server_time_ms: 1_699_999_000_000,
      }),
    });
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <WorkstationProvider ws={store}>
          <TerminalPanel />
        </WorkstationProvider>
      </WorkspaceProvider>
    ));
    expect(screen.getByText(/AWAITING FEED/)).toBeTruthy();
    expect(screen.getAllByText("No depth").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByRole("group", { name: /price chart/i })).toBeTruthy();
  });
});
