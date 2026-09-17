import { expect, test } from "@playwright/test";
import {
  configureSession,
  handoffKey,
  randomKeyB64,
  resetServer,
  searchAndSelectToken,
  setCommandResponse,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

const ALL_TRUE_BOOTSTRAP = {
  protocol_version: 1,
  capabilities: {
    market: true,
    chart: true,
    realtime: true,
    quotes: true,
    preview: true,
    execute: true,
    limits: true,
    portfolio: true,
    intelligence: true,
    twitter: true,
    gmgn: true,
    okx: true,
    twap: true,
    rfq: true,
    withdraw: true,
  },
  trading_enabled: true,
  kill_switch: { enabled: false, reason: null },
  chains: [{ id: "base", display: "Base", enabled: true }],
  session: { key_id: "kid-e2e", expires_at_ms: 4_000_000_000_000 },
  server_time_ms: 1_700_000_000_000,
};

/**
 * One search + detail body, so a ticket target can be resolved through the real
 * top-bar search even while every mutation is gated off.
 */
const TARGET_RESPONSE = {
  result: {
    results: [
      {
        chain: "base",
        address: "0x00000000000000000000000000000000000000a1",
        symbol: "SOL",
        name: "Wrapped SOL",
      },
    ],
    token: {
      chain: "base",
      address: "0x00000000000000000000000000000000000000a1",
      symbol: "SOL",
      name: "Wrapped SOL",
      decimals: 9,
    },
    stats: {
      priceUsd: 150,
      priceChange24h: 1.5,
      marketCapUsd: 1_000_000,
      liquidityUsd: 250_000,
      volume24hUsd: 50_000,
      holders: 1_200,
    },
    risk: {
      score: 12,
      factors: [],
      buyTaxBps: 0,
      sellTaxBps: 0,
      transferFeeBps: 0,
      sellRestricted: false,
      simulated: true,
    },
    evidence: [],
    slot: 1,
    sourceAgeMs: 0,
  },
};

test.describe("fail-closed private workspace", () => {
  test("renders an explicit unavailable state and enables no capability on 404", async ({ page }) => {
    let bootstrapHits = 0;
    await page.route("**/v1/bootstrap", (route) => {
      bootstrapHits += 1;
      return route.fulfill({ status: 404, body: "not found" });
    });
    await page.goto("/");
    // Bootstrap is opaque now: it needs a BR-5 key before the routed 404 can be
    // observed (with no key it fails closed locally instead of probing).
    await handoffKey(page, randomKeyB64(), randomKeyB64());

    await expect(page.locator(".terminal.workspace")).toBeVisible();
    // The offline banner carries the typed fail-closed reason into the top bar.
    await expect(page.getByText(/not available on this deployment/i).first()).toBeVisible();
    // Positive control: the fail-closed state came from the routed 404, not from
    // a local no-op. A regression that stopped probing (or a hidden fallback that
    // rendered the same text without a request) now fails this assertion.
    expect(bootstrapHits).toBeGreaterThan(0);
    // No capability was enabled optimistically: the single trading gate reads
    // disabled and no mutation surface advertises an enabled state.
    await expect(page.getByTestId("trading-gate")).toHaveText("TRADING DISABLED");
    await expect(page.getByText("TRADING ENABLED")).toHaveCount(0);
  });

  test("maps an unauthorized bootstrap to an auth error, never a ready state", async ({ page }) => {
    await page.route("**/v1/bootstrap", (route) => route.fulfill({ status: 401, body: "no" }));
    await page.goto("/");
    await handoffKey(page, randomKeyB64(), randomKeyB64());

    await expect(page.getByText(/not authorized/i).first()).toBeVisible();
    await expect(page.getByTestId("trading-gate")).toHaveText("TRADING DISABLED");
    await expect(page.getByText("TRADING ENABLED")).toHaveCount(0);
  });

  test("disables every mutation with a reason while the kill switch is engaged", async ({ page, request }) => {
    await resetServer(request);
    const s2c = randomKeyB64();
    const c2s = randomKeyB64();
    await configureSession(request, s2c, c2s);
    await request.post("/__test__/bootstrap", {
      data: {
        bootstrap: {
          ...ALL_TRUE_BOOTSTRAP,
          trading_enabled: false,
          kill_switch: { enabled: true, reason: "foundation phase" },
        },
      },
    });
    await setCommandResponse(request, TARGET_RESPONSE);
    await page.goto("/");
    await waitForWorkspace(page);
    await handoffKey(page, s2c, c2s);
    await waitForSocket(request);

    // The fail-closed state is surfaced in the top bar: the trading gate is off
    // and the engaged kill switch carries its reason.
    await expect(page.getByTestId("trading-gate")).toHaveText("TRADING DISABLED");
    await expect(page.getByTestId("kill-switch")).toBeVisible();
    await expect(page.getByTestId("kill-switch")).toHaveAttribute("title", /foundation phase/);

    // Resolve the ticket target through the top-bar search so the mutation
    // controls (and their disabled reasons) actually render.
    await searchAndSelectToken(page, "SOL", "SOL");
    await expect(page.getByTestId("selected-instrument")).toContainText("SOL");

    await expect(page.getByRole("button", { name: /execute buy/i })).toBeDisabled();
    await expect(page.getByText(/trading is disabled|foundation phase/i).first()).toBeVisible();

    await page.getByTestId("ticket-tab-limit").click();
    await expect(page.getByRole("button", { name: /place limit order/i })).toBeDisabled();
  });

  test("shows no fabricated market values before any authenticated frame arrives", async ({ page, request }) => {
    await resetServer(request);
    const s2c = randomKeyB64();
    const c2s = randomKeyB64();
    await configureSession(request, s2c, c2s);
    await page.goto("/");
    await waitForWorkspace(page);
    // The stream key is handed over (so bootstrap succeeds), but no frame is
    // ever sent: the view must stay on "awaiting feed", not fabricate depth.
    await handoffKey(page, s2c, c2s);
    await expect(page.locator(".terminal.workspace")).toBeVisible();

    // The centre chart pane is always mounted; there is no terminal tab to open.
    await expect(page.getByText("AWAITING FEED")).toBeVisible();
    await expect(page.locator(".depth-list__row")).toHaveCount(0);
    await expect(page.getByText(/no depth/i).first()).toBeVisible();
  });
});
