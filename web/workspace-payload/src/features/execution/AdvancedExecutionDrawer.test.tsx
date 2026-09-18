import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { TradeTicket } from "../../components/layout/TradeTicket";
import { createStore, renderStation, makeCommand, SOL_A } from "../intelligence/test-support";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const DETAIL = {
  token: { chain: "solana", address: SOL_A.address, symbol: "AAA", name: "Token A" },
  stats: {
    priceUsd: 1.5,
    priceChange24h: 1,
    marketCapUsd: 1500,
    liquidityUsd: 250,
    volume24hUsd: 500,
    holders: 10,
  },
  risk: null,
  evidence: [],
  slot: null,
  sourceAgeMs: 0,
};

describe("Advanced execution drawer (ticket -> Advanced)", () => {
  afterEach(() => cleanup());

  it("mounts the mutating TWAP/RFQ controls in the ticket's Advanced area with gates intact", async () => {
    const store = createStore(
      makeCommand({
        get_token: () => DETAIL,
        get_execution_progress: () => null,
      }),
      {
        selected: SOL_A,
        capabilities: { twap: true, rfq: true, preview: true, execute: true },
      },
    );
    await flush();
    renderStation(store, () => <TradeTicket />);
    await flush();

    const advanced = screen.getByTestId("ticket-advanced");
    const trigger = screen.getByTestId("advanced-execution-open");
    expect(advanced.contains(trigger)).toBe(true);

    fireEvent.click(trigger);
    await waitFor(() =>
      expect(screen.getByRole("dialog", { name: "Advanced execution" })).toBeTruthy(),
    );

    const dialog = screen.getByRole("dialog", { name: "Advanced execution" });
    expect(dialog.textContent).toMatch(/Adaptive TWAP/);
    expect(dialog.textContent).toMatch(/RFQ \/ solver competition/);

    // TRADING_ENABLED is false in this session, so both mutating actions fail closed.
    const twap = screen.getByRole("button", { name: "Start adaptive TWAP" }) as HTMLButtonElement;
    const rfq = screen.getByRole("button", { name: "Request quotes" }) as HTMLButtonElement;
    expect(twap.disabled).toBe(true);
    expect(rfq.disabled).toBe(true);
  });

  it("closes on Escape and returns focus to the invoking control", async () => {
    const store = createStore(makeCommand({ get_token: () => DETAIL }), {
      selected: SOL_A,
      capabilities: { twap: true, rfq: true },
    });
    await flush();
    renderStation(store, () => <TradeTicket />);
    await flush();

    const trigger = screen.getByTestId("advanced-execution-open") as HTMLButtonElement;
    fireEvent.click(trigger);
    await waitFor(() =>
      expect(screen.getByRole("dialog", { name: "Advanced execution" })).toBeTruthy(),
    );

    fireEvent.keyDown(document.body, { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("dialog", { name: "Advanced execution" })).toBeNull(),
    );
    expect(document.activeElement).toBe(trigger);
  });

  it("keeps the TWAP UNKNOWN guard when the drawer is closed and reopened", async () => {
    const store = createStore(
      makeCommand({
        get_token: () => DETAIL,
        get_execution_progress: () => null,
        start_twap: () => {
          throw new Error("gateway timeout");
        },
      }),
      {
        selected: SOL_A,
        capabilities: { twap: true, rfq: true },
        tradingEnabled: true,
      },
    );
    await flush();
    // A capital-committing mutation requires fresh authoritative realtime state.
    store.setConnection({
      phase: "live",
      lastFrameAtMs: 1_700_000_000_000,
      attempt: 0,
      nextRetryAtMs: null,
      reason: null,
    });
    renderStation(store, () => <TradeTicket />);
    await flush();

    fireEvent.click(screen.getByTestId("advanced-execution-open"));
    await waitFor(() =>
      expect(screen.getByRole("dialog", { name: "Advanced execution" })).toBeTruthy(),
    );
    fireEvent.input(screen.getByLabelText("TWAP total amount"), { target: { value: "100" } });
    await flush();
    fireEvent.click(screen.getByRole("button", { name: "Start adaptive TWAP" }));
    await waitFor(() =>
      expect(screen.getByText(/TWAP submission outcome UNKNOWN/)).toBeTruthy(),
    );

    // The panel is hidden, not unmounted, so the unresolved guard survives.
    fireEvent.keyDown(document.body, { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("dialog", { name: "Advanced execution" })).toBeNull(),
    );
    fireEvent.click(screen.getByTestId("advanced-execution-open"));
    await waitFor(() =>
      expect(screen.getByRole("dialog", { name: "Advanced execution" })).toBeTruthy(),
    );
    expect(screen.getByText(/TWAP submission outcome UNKNOWN/)).toBeTruthy();
    // The two-step release state survived the close/reopen.
    expect(screen.getByRole("button", { name: "Retry same request" })).toBeTruthy();
    expect(screen.getByLabelText("I verified the earlier TWAP out-of-band")).toBeTruthy();
  });
});
