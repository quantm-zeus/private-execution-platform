import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { AppShell } from "../app/AppShell";
import { WorkspaceProvider, createWorkspaceStore } from "../state/session";
import { parseWorkspaceSession } from "../transport/bootstrap";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/**
 * Runtime proof that navigating every private surface writes nothing to
 * persistent browser storage. The static scan in verify-web-boundary covers the
 * source; this covers the rendered application.
 */
describe("no plaintext persistence", () => {
  afterEach(() => {
    cleanup();
    localStorage.clear();
    sessionStorage.clear();
  });

  it("writes no private state to localStorage/sessionStorage/cookies across all views", async () => {
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
        },
        trading_enabled: true,
        kill_switch: { enabled: false, reason: null },
        chains: [{ id: "base", display: "Base", enabled: true }],
        session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
        server_time_ms: 1_699_999_000_000,
      }),
    });
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <AppShell />
      </WorkspaceProvider>
    ));

    for (const label of [
      "Discover",
      "Terminal",
      "Trade",
      "Limits",
      "Execution",
      "Portfolio",
      "Intelligence",
      "Security",
      "Overview",
    ]) {
      fireEvent.click(screen.getByRole("button", { name: new RegExp(`^${label}`) }));
      await flush();
    }

    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).toBe("");
  });
});
