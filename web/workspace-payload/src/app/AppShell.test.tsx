import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { AppShell } from "./AppShell";
import { WorkspaceProvider, createWorkspaceStore } from "../state/session";
import { parseWorkspaceSession } from "../transport/bootstrap";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

async function readyStore() {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { market: true, realtime: true },
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

describe("AppShell", () => {
  afterEach(() => cleanup());

  it("renders the terminal shell with navigation and a workspace title", async () => {
    const store = await readyStore();
    render(() => (
      <WorkspaceProvider store={store}>
        <AppShell />
      </WorkspaceProvider>
    ));
    expect(screen.getByRole("heading", { name: /evergreen private workspace/i })).toBeTruthy();
    expect(screen.getByRole("navigation", { name: /workspace sections/i })).toBeTruthy();
    for (const label of ["Overview", "Discover", "Terminal", "Trade", "Limits", "Portfolio", "Security"]) {
      expect(screen.getByRole("button", { name: new RegExp(label) })).toBeTruthy();
    }
    expect(screen.getByRole("button", { name: /lock/i })).toBeTruthy();
  });

  it("shows the shared target in the header, or an explicit empty state", async () => {
    const store = await readyStore();
    render(() => (
      <WorkspaceProvider store={store}>
        <AppShell />
      </WorkspaceProvider>
    ));
    const target = screen.getByTestId("selected-instrument");
    expect(target.textContent).toMatch(/no target selected/i);

    store.setSelectedInstrument({
      chain: "base",
      address: "0x1234567890abcdef1234567890abcdef12345678",
      symbol: "PEPE",
    });
    await flush();

    expect(target.textContent).toMatch(/PEPE/);
    expect(target.textContent).toMatch(/0x1234/);
    expect(target.textContent).toMatch(/base/);
  });

  it("switches the main surface when navigation changes", async () => {
    const store = await readyStore();
    render(() => (
      <WorkspaceProvider store={store}>
        <AppShell />
      </WorkspaceProvider>
    ));
    fireEvent.click(screen.getByRole("button", { name: /^Trade/ }));
    expect(document.getElementById("view-title")?.textContent).toBe("Trade");
    fireEvent.click(screen.getByRole("button", { name: /^Portfolio/ }));
    expect(document.getElementById("view-title")?.textContent).toBe("Portfolio");
    expect(document.body.textContent).not.toMatch(/wallet address/i);
  });

  it("keeps a visited view mounted so submission state survives navigation", async () => {
    const store = await readyStore();
    render(() => (
      <WorkspaceProvider store={store}>
        <AppShell />
      </WorkspaceProvider>
    ));
    fireEvent.click(screen.getByRole("button", { name: /^Trade/ }));
    const tradeNode = document.querySelector('[aria-label="Market ticket"]');
    expect(tradeNode).not.toBeNull();

    // Navigating away must hide — not unmount — the panel: an UNKNOWN outcome and
    // its idempotency key live in the panel and would be lost on remount.
    fireEvent.click(screen.getByRole("button", { name: /^Portfolio/ }));
    const stillMounted = document.querySelector('[aria-label="Market ticket"]');
    expect(stillMounted).toBe(tradeNode);
    expect(
      (stillMounted as HTMLElement).closest(".view-slot")?.classList.contains("view-slot--hidden"),
    ).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: /^Trade/ }));
    expect(document.querySelector('[aria-label="Market ticket"]')).toBe(tradeNode);
  });

  it("keeps trading controls disabled and explains the missing capability", async () => {
    const store = await readyStore();
    render(() => (
      <WorkspaceProvider store={store}>
        <AppShell />
      </WorkspaceProvider>
    ));
    fireEvent.click(screen.getByRole("button", { name: /^Trade/ }));
    const execute = screen.getByRole("button", { name: /execute buy/i });
    expect((execute as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getAllByText(/capability "execute" is not available/i).length).toBeGreaterThan(0);
  });

  it("keeps focus in the nav rail during arrow traversal", async () => {
    const store = await readyStore();
    render(() => (
      <WorkspaceProvider store={store}>
        <AppShell />
      </WorkspaceProvider>
    ));
    const trade = screen.getByRole("button", { name: /^Trade/ });
    trade.focus();
    fireEvent.keyDown(trade, { key: "ArrowDown" });
    // The microtask that would move focus to <main> must not fire for a
    // keyboard traversal, or the next arrow key would leave the rail.
    await flush();
    const limits = screen.getByRole("button", { name: /^Limits/ });
    expect(document.activeElement).toBe(limits);
    expect(document.getElementById("view-title")?.textContent).toBe("Limits");
  });
});
