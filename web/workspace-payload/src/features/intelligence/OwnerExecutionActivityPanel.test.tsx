import { afterEach, describe, expect, it } from "vitest";
import { cleanup, screen, waitFor } from "@solidjs/testing-library";
import { OwnerExecutionActivityPanel } from "./OwnerExecutionActivityPanel";
import { createStore, renderStation, makeCommand } from "./test-support";
import type { ExecutionProgress } from "../../contracts/execution";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const RUNNING: ExecutionProgress = {
  executionId: "exec_7f3a91c4",
  kind: "twap",
  state: "running",
  chunksTotal: 6,
  chunksDone: 4,
  filledAmount: "12.40 SOL",
  remainingAmount: "5.60 SOL",
  realizedVsEstimateBps: -18,
  haltReason: null,
};

describe("OwnerExecutionActivityPanel (Activity > Mine)", () => {
  afterEach(() => cleanup());

  it("renders an active execution truthfully and contains no mutating control", async () => {
    const store = createStore(
      makeCommand({ get_execution_progress: () => RUNNING }),
      { selected: { chain: "solana", address: "TokenA", symbol: "AAA" } },
    );
    await flush();
    renderStation(store, () => <OwnerExecutionActivityPanel />);
    await waitFor(() => expect(screen.getByTestId("activity-mine")).toBeTruthy());
    await waitFor(() => expect(screen.getByText("Running")).toBeTruthy());

    expect(screen.getByText("exec_7f3a91c4")).toBeTruthy();
    expect(screen.getByText("4/6")).toBeTruthy();
    expect(screen.getByText("12.40 SOL")).toBeTruthy();
    expect(screen.getByText("-18 bps")).toBeTruthy();

    const mine = screen.getByTestId("activity-mine");
    expect(mine.querySelectorAll("button")).toHaveLength(0);
    expect(mine.querySelectorAll("input")).toHaveLength(0);
    // The history row is permanently and honestly unavailable.
    expect(screen.getByTestId("mine-history").textContent).toMatch(/No authoritative execution-history/);
  });

  it("distinguishes idle (succeeded, nothing running) from unavailable", async () => {
    const idle = createStore(makeCommand({ get_execution_progress: () => null }), {
      selected: { chain: "solana", address: "TokenA", symbol: "AAA" },
    });
    await flush();
    renderStation(idle, () => <OwnerExecutionActivityPanel />);
    await waitFor(() =>
      expect(screen.getByText("No execution is running for this workspace.")).toBeTruthy(),
    );
    expect(screen.getByText("Idle")).toBeTruthy();
    cleanup();

    // No command channel: it must surface as awaiting the channel, never idle.
    const blocked = createStore(makeCommand(), {
      selected: { chain: "solana", address: "TokenA", symbol: "AAA" },
      failClosed: true,
    });
    await flush();
    renderStation(blocked, () => <OwnerExecutionActivityPanel />);
    await waitFor(() =>
      expect(screen.getByText(/Awaiting the authenticated command channel/)).toBeTruthy(),
    );
    expect(screen.queryByText("No execution is running for this workspace.")).toBeNull();
  });

  it("renders halt reason only when present and omits the bar without a denominator", async () => {
    const halted = createStore(
      makeCommand({
        get_execution_progress: () => ({
          ...RUNNING,
          state: "halted",
          chunksTotal: null,
          chunksDone: null,
          haltReason: "Liquidity recovery stayed below the floor.",
        }),
      }),
      { selected: { chain: "solana", address: "TokenA", symbol: "AAA" } },
    );
    await flush();
    renderStation(halted, () => <OwnerExecutionActivityPanel />);
    await waitFor(() => expect(screen.getByText("Halted")).toBeTruthy());
    expect(screen.getByText("Liquidity recovery stayed below the floor.")).toBeTruthy();
    // No positive denominator: the bar is omitted and progress is unknown.
    expect(screen.getByText("Progress —")).toBeTruthy();
    expect(document.querySelector(".grad--exec .grad__fill")).toBeNull();
  });
});
