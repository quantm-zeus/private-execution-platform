import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { HolderTradersPanel } from "./HolderTradersPanel";
import { createStore, renderStation, makeCommand, SOL_A, SOL_B } from "./test-support";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function holdersFor(address: string, followed: boolean) {
  return {
    chain: "solana",
    address,
    holders: [
      {
        user: {
          handle: "@whale",
          displayName: "Whale",
          verified: true,
          followed,
          dev: true,
          clan: "CLAN",
          followers: 48_200,
        },
        wallet: "Wallet111",
        amount: 1000,
        valueUsd: 48_210,
        averageEntryPriceUsd: 60.5,
        currentPriceUsd: 70,
        realizedPnlUsd: 100,
        unrealizedPnlUsd: 500,
        totalPnlUsd: 600,
        averageHoldTimeSeconds: 12 * 86_400,
        thesis: { text: "conviction thesis", createdAtMs: 1_700_000_000_000, likes: 42, tradeId: null },
      },
      {
        user: { handle: "@anon", followers: null },
        wallet: "Wallet222",
        amount: null,
        valueUsd: 100,
        averageEntryPriceUsd: null,
        currentPriceUsd: 20,
        realizedPnlUsd: null,
        unrealizedPnlUsd: null,
        totalPnlUsd: null,
        averageHoldTimeSeconds: null,
        thesis: null,
      },
    ],
  };
}

function command(followed: boolean) {
  return makeCommand({
    get_token_holders: (payload) =>
      holdersFor((payload as { address: string }).address, followed),
  });
}

describe("HolderTradersPanel", () => {
  afterEach(() => cleanup());

  it("defaults to the provider order, sorts, and returns to provider order", async () => {
    const store = createStore(command(false), { selected: SOL_A });
    await flush();
    renderStation(store, () => <HolderTradersPanel />);
    await waitFor(() => expect(screen.getAllByTestId("trader-row")).toHaveLength(2));

    let rows = screen.getAllByTestId("trader-row");
    expect(rows[0]!.textContent).toMatch(/Whale/);
    expect(screen.getByTestId("holders-pane").textContent).toMatch(/FOMO order/);

    fireEvent.click(screen.getByTestId("holder-sort-value"));
    await flush();
    rows = screen.getAllByTestId("trader-row");
    expect(rows[0]!.textContent).toMatch(/Whale/);
    expect(screen.getByTestId("holder-sort-value").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("holders-pane").textContent).toMatch(/sorted by value/);

    // Pressing the active segment returns to the provider's authoritative order.
    fireEvent.click(screen.getByTestId("holder-sort-value"));
    await flush();
    expect(screen.getByTestId("holder-sort-value").getAttribute("aria-pressed")).toBe("false");
    expect(screen.getByTestId("holders-pane").textContent).toMatch(/FOMO order/);
  });

  it("offers Following only when the provider proves followed rows", async () => {
    const without = createStore(command(false), { selected: SOL_A });
    await flush();
    renderStation(without, () => <HolderTradersPanel />);
    await waitFor(() => expect(screen.getAllByTestId("trader-row")).toHaveLength(2));
    expect(screen.queryByTestId("holder-scope-following")).toBeNull();
    cleanup();

    const withFollowed = createStore(command(true), { selected: SOL_A });
    await flush();
    renderStation(withFollowed, () => <HolderTradersPanel />);
    await waitFor(() => expect(screen.getByTestId("holder-scope-following")).toBeTruthy());
    fireEvent.click(screen.getByTestId("holder-scope-following"));
    await flush();
    expect(screen.getByTestId("holder-scope-following").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getAllByTestId("trader-row")).toHaveLength(1);
  });

  it("falls back visibly to Top holders when Following becomes unprovable", async () => {
    const switching = makeCommand({
      get_token_holders: (payload) => {
        const address = (payload as { address: string }).address;
        return holdersFor(address, address === SOL_A.address);
      },
    });
    const store = createStore(switching, { selected: SOL_A });
    await flush();
    renderStation(store, () => <HolderTradersPanel />);
    await waitFor(() => expect(screen.getByTestId("holder-scope-following")).toBeTruthy());
    fireEvent.click(screen.getByTestId("holder-scope-following"));
    await flush();
    expect(screen.getByTestId("holder-scope-following").getAttribute("aria-pressed")).toBe("true");

    // Switch to a token whose provider returns no followed rows.
    store.setSelectedInstrument(SOL_B);
    await waitFor(() => expect(screen.queryByTestId("holder-scope-following")).toBeNull());
    expect(screen.getByTestId("holder-scope-top").getAttribute("aria-pressed")).toBe("true");
  });

  it("states an absent thesis and keeps the address tertiary", async () => {
    const store = createStore(command(false), { selected: SOL_A });
    await flush();
    renderStation(store, () => <HolderTradersPanel />);
    await waitFor(() => expect(screen.getAllByTestId("trader-row")).toHaveLength(2));

    const rows = screen.getAllByTestId("trader-row");
    expect(rows[0]!.textContent).toMatch(/conviction thesis/);
    expect(rows[1]!.textContent).toMatch(/No thesis authored for this token/);
    // The wallet address is never in the row.
    expect(rows[0]!.textContent).not.toMatch(/Wallet111/);

    fireEvent.click(rows[1]!);
    await flush();
    const detail = screen.getByTestId("trader-detail");
    expect(detail.textContent).toMatch(/This trader has not authored a thesis/);
    // Unknown values stay — rather than a fabricated zero.
    expect(detail.textContent).toMatch(/Token amount\s*—/);
    expect(detail.querySelector(".address-copy")).not.toBeNull();
  });
});
