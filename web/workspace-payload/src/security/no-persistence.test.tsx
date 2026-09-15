import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { AppShell } from "../app/AppShell";
import { WorkspaceProvider, createWorkspaceStore } from "../state/session";
import { parseWorkspaceSession } from "../transport/bootstrap";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/** A fully-capable in-memory session so every private view can mount. */
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
      },
      trading_enabled: true,
      kill_switch: { enabled: false, reason: null },
      chains: [{ id: "base", display: "Base", enabled: true }],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.reload();
  return store;
}

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
    const store = createRenderableStore();
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
    // Mounting and navigating all nine private views is legitimately slow under
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
    render(() => (
      <WorkspaceProvider store={store}>
        <AppShell />
      </WorkspaceProvider>
    ));

    const urlBefore = location.href;
    const titleBefore = document.title;
    const historyBefore = history.length;

    fireEvent.click(screen.getByRole("button", { name: /^Trade/ }));
    await flush();

    const local = screen.getByRole("button", { name: "Local Router" });
    expect(screen.getByRole("button", { name: "OKX" }).getAttribute("aria-pressed")).toBe("true");
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
