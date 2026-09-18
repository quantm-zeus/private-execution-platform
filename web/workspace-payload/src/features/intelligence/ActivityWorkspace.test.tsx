import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { ActivityWorkspace } from "./ActivityWorkspace";
import { createStore, renderStation, makeCommand, SOL_A, SOL_B } from "./test-support";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function activityFor(address: string, handle: string) {
  return {
    chain: "solana",
    address,
    events: [
      {
        type: "buy",
        rawType: "swap_buy",
        user: { handle },
        usdAmount: 18_400,
        priceUsd: 104.39,
        marketCapUsd: 1_200_000_000,
        createdAtMs: 1_699_999_990_000,
      },
    ],
    count: 1,
    nextCursor: null,
    hasNextPage: false,
    source: null,
    sourceAgeMs: null,
  };
}

describe("ActivityWorkspace", () => {
  afterEach(() => cleanup());

  it("auto-selects Token for a selected exact token and never mixes Mine into it", async () => {
    const store = createStore(
      makeCommand({ get_token_activity: () => activityFor(SOL_A.address, "@tape_reader") }),
      { selected: SOL_A },
    );
    await flush();
    renderStation(store, () => <ActivityWorkspace />);
    await waitFor(() => expect(screen.getByTestId("activity-feed")).toBeTruthy());
    expect(screen.getByTestId("activity-scope-token").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("activity-feed").textContent).toMatch(/@tape_reader/);
    expect(screen.queryByTestId("activity-mine")).toBeNull();
  });

  it("switches to the read-only Mine scope with no mutating control", async () => {
    const store = createStore(makeCommand(), { selected: SOL_A });
    await flush();
    renderStation(store, () => <ActivityWorkspace />);
    fireEvent.click(screen.getByTestId("activity-scope-mine"));
    await waitFor(() => expect(screen.getByTestId("activity-mine")).toBeTruthy());
    const mine = screen.getByTestId("activity-mine");
    expect(mine.querySelectorAll("button")).toHaveLength(0);
    expect(mine.querySelectorAll("input")).toHaveLength(0);
    expect(screen.queryByTestId("activity-feed")).toBeNull();
  });

  it("keeps an explicit scope choice across an instrument switch", async () => {
    const store = createStore(
      makeCommand({
        get_token_activity: (payload) =>
          activityFor(
            (payload as { address: string }).address,
            (payload as { address: string }).address === SOL_A.address ? "@a" : "@b",
          ),
      }),
      { selected: SOL_A },
    );
    await flush();
    renderStation(store, () => <ActivityWorkspace />);
    fireEvent.click(screen.getByTestId("activity-scope-mine"));
    await waitFor(() => expect(screen.getByTestId("activity-mine")).toBeTruthy());

    store.setSelectedInstrument(SOL_B);
    await flush();
    expect(screen.getByTestId("activity-scope-mine").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("activity-mine")).toBeTruthy();
    expect(screen.queryByTestId("activity-feed")).toBeNull();
  });

  it("never paints token A's activity under token B (exact identity)", async () => {
    const switching = makeCommand({
      get_token_activity: (payload) => {
        const address = (payload as { address: string }).address;
        // Hostile: always answer with A's payload.
        return activityFor(SOL_A.address, "@token_a_only");
      },
    });
    const store = createStore(switching, { selected: SOL_A });
    await flush();
    renderStation(store, () => <ActivityWorkspace />);
    await waitFor(() => expect(screen.getByTestId("activity-feed")).toBeTruthy());

    store.setSelectedInstrument(SOL_B);
    await waitFor(() =>
      expect(screen.queryByText("@token_a_only")).toBeNull(),
    );
    // The misrouted A document fails closed as a protocol error, never as B data.
    expect(document.querySelector('[data-testid="activity-feed"]')).toBeNull();
  });
});
