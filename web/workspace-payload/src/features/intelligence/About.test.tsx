import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, screen, waitFor } from "@solidjs/testing-library";
import { TokenOverviewPanel } from "./TokenOverviewPanel";
import { createStore, renderStation, makeCommand, SOL_A } from "./test-support";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const ABOUT = {
  token: {
    chain: "solana",
    address: SOL_A.address,
    symbol: "AAA",
    name: "Token A",
    imageUrl: null,
    socialLinks: {
      twitter: "javascript:alert(1)",
      website: "https://example.com",
    },
  },
  profile: {
    launchpad: "pump.fun",
    graduationPercent: 100,
    createdAtMs: 1_700_000_000_000,
    circulatingSupply: 1000,
    totalSupply: 2000,
  },
  stats: {
    priceUsd: 1.5,
    priceChange24h: -2.5,
    marketCapUsd: 1500,
    fdvUsd: null,
    liquidityUsd: 250,
    volume24hUsd: 500,
    holders: 1200,
    top10HoldersPercent: 42,
  },
  trading: {
    "5m": null,
    "1h": { buyCount: 0, sellCount: 0, buyVolumeUsd: 0, sellVolumeUsd: 0, uniqueBuyers: 0, uniqueSellers: 0 },
    "4h": null,
    "24h": null,
  },
  warnings: [],
  risk: {
    score: null,
    factors: [],
    buyTaxBps: null,
    sellTaxBps: null,
    transferFeeBps: null,
    sellRestricted: null,
    simulated: false,
    level: null,
  },
  source: null,
  sourceAgeMs: null,
};

function aboutCommand() {
  return makeCommand({ get_token_about: () => ABOUT });
}

describe("TokenOverviewPanel (About)", () => {
  afterEach(() => cleanup());

  it("renders the five calm sections and no activity feed", async () => {
    const store = createStore(aboutCommand(), { selected: SOL_A });
    await flush();
    renderStation(store, () => <TokenOverviewPanel />);
    await waitFor(() => expect(screen.getByTestId("about-pane")).toBeTruthy());
    await waitFor(() => expect(screen.getByTestId("about-profile")).toBeTruthy());

    for (const id of ["about-profile", "about-market", "about-supply", "about-flow", "about-risk"]) {
      expect(screen.getByTestId(id)).toBeTruthy();
    }
    // The feed has exactly one home: About renders no list, pager or activity.
    expect(document.querySelector(".feed__row")).toBeNull();
    expect(document.querySelector(".pager")).toBeNull();
    expect(document.querySelector('[data-testid="activity-feed"]')).toBeNull();
    expect(document.querySelector('[data-testid="activity-pane"]')).toBeNull();
  });

  it("omits the ratio bar when the window has no trades", async () => {
    const store = createStore(aboutCommand(), { selected: SOL_A });
    await flush();
    renderStation(store, () => <TokenOverviewPanel />);
    await waitFor(() => expect(screen.getByTestId("about-flow")).toBeTruthy());

    expect(screen.getByTestId("about-flow").textContent).toMatch(/No trades in this window/);
    expect(document.querySelector(".ratio__buy")).toBeNull();
    expect(document.querySelector(".ratio__sell")).toBeNull();
  });

  it("keeps risk unknown and tax — rather than inventing a value", async () => {
    const store = createStore(aboutCommand(), { selected: SOL_A });
    await flush();
    renderStation(store, () => <TokenOverviewPanel />);
    await waitFor(() => expect(screen.getByTestId("about-risk")).toBeTruthy());

    const risk = screen.getByTestId("about-risk");
    expect(risk.textContent).toMatch(/Unknown/);
    expect(risk.textContent).not.toMatch(/Clear|Hard risk/);
    expect(risk.textContent).toMatch(/Buy tax\s*—/);
    expect(risk.textContent).toMatch(/Sell tax\s*—/);
    expect(risk.textContent).toMatch(/No provider warnings reported/);
  });

  it("drops a hostile social link and keeps a safe one announced", async () => {
    const store = createStore(aboutCommand(), { selected: SOL_A });
    await flush();
    renderStation(store, () => <TokenOverviewPanel />);
    await waitFor(() => expect(screen.getByTestId("about-profile")).toBeTruthy());

    expect(document.querySelector('a[href^="javascript:"]')).toBeNull();
    const link = screen.getByRole("link", { name: /Website/ });
    expect(link.getAttribute("target")).toBe("_blank");
    expect(link.getAttribute("rel")).toBe("noopener noreferrer");
  });

  it("sets the graduation fill through CSSOM", async () => {
    const store = createStore(aboutCommand(), { selected: SOL_A });
    await flush();
    renderStation(store, () => <TokenOverviewPanel />);
    await waitFor(() => expect(screen.getByTestId("about-profile")).toBeTruthy());
    const fill = screen.getByTestId("about-profile").querySelector<HTMLElement>(".grad__fill");
    expect(fill).not.toBeNull();
    expect(fill!.style.width).toBe("100%");
  });
});
