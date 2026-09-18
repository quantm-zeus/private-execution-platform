import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import {
  configureSession,
  handoffKey,
  marketPriceFrame,
  marketStatusFrame,
  marketTrendingFrame,
  randomKeyB64,
  resetServer,
  searchAndSelectToken,
  sendFrames,
  setCommandResponse,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/**
 * WS-first market lane over the existing encrypted PEP WebSocket:
 * pushed normalized `market` frames drive the trending rail and the selected
 * token's header price, with honest provenance and exact-entity isolation.
 * There is no second browser channel and no direct browser -> provider call.
 */

const TOKEN_ADDRESS = "0x00000000000000000000000000000000000000a1";
const OTHER_ADDRESS = "0x00000000000000000000000000000000000000b2";

const TARGET_RESPONSE = {
  result: {
    results: [
      {
        chain: "base",
        address: TOKEN_ADDRESS,
        symbol: "SOL",
        name: "Wrapped SOL",
        priceUsd: 150.25,
        marketCapUsd: 68_000_000,
        rank: 4,
      },
    ],
    token: { chain: "base", address: TOKEN_ADDRESS, symbol: "SOL", name: "Wrapped SOL" },
    stats: {
      priceUsd: 150.25,
      priceChange24h: 1.5,
      marketCapUsd: 68_000_000,
      liquidityUsd: 250_000,
      volume24hUsd: 50_000,
      holders: 1_200,
    },
    risk: {
      score: null,
      factors: [],
      buyTaxBps: null,
      sellTaxBps: null,
      transferFeeBps: null,
      sellRestricted: null,
      simulated: false,
      level: "clear",
    },
    evidence: [],
    slot: 1,
    sourceAgeMs: 0,
  },
};

async function bootLive(page: Page, request: APIRequestContext): Promise<void> {
  await resetServer(request);
  const s2c = randomKeyB64();
  const c2s = randomKeyB64();
  await configureSession(request, s2c, c2s);
  await page.goto("/");
  await waitForWorkspace(page);
  await handoffKey(page, s2c, c2s);
  await waitForSocket(request);
}

test.describe("WS-first market lane", () => {
  test("pushed trending rows render with LIVE WS provenance and a working network filter", async ({
    page,
    request,
  }) => {
    await bootLive(page, request);

    await sendFrames(request, {
      frames: [
        // The encrypted stream must begin with an authenticated snapshot.
        marketStatusFrame("fomo-ws"),
        marketTrendingFrame([
          { chain: "base", address: TOKEN_ADDRESS, symbol: "SOL", priceUsd: 150.25, priceChange24h: 2.5, marketCapUsd: 68_000_000, liquidityUsd: 250_000, volume24hUsd: 50_000, rank: 1 },
          { chain: "solana", address: "So11111111111111111111111111111111111111112", symbol: "WIF", priceUsd: 2.5, priceChange24h: -1.25, rank: 2 },
        ]),
      ],
    });

    const rows = page.getByTestId("trending-tokens").locator(".market-item");
    await expect(rows).toHaveCount(2);
    await expect(page.getByTestId("trending-source")).toHaveText("LIVE WS");
    await expect(page.getByTestId("chain-filter-all")).toContainText("2");
    await expect(page.getByTestId("chain-filter-base")).toContainText("Base");
    await expect(page.getByTestId("chain-filter-solana")).toContainText("Solana");

    // Filtering is local and honest: Solana shows exactly its one row.
    await page.getByTestId("chain-filter-solana").click();
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText("WIF");
    await page.getByTestId("chain-filter-all").click();
    await expect(rows).toHaveCount(2);
  });

  test("a pushed price tick updates the exact selected entity only", async ({ page, request }) => {
    await bootLive(page, request);
    await setCommandResponse(request, TARGET_RESPONSE);
    await searchAndSelectToken(page, "SOL", "SOL");
    await expect(page.getByTestId("selected-instrument")).toContainText("SOL");

    // The authoritative detail renders first.
    await expect(page.getByTestId("token-stat-price")).toContainText("150.25");

    // A pushed tick for the exact entity moves the header price.
    await sendFrames(request, {
      frames: [
        marketStatusFrame("fomo-ws"),
        marketPriceFrame("base", TOKEN_ADDRESS, 999, { source: "fomo-ws" }),
      ],
    });
    await expect(page.getByTestId("token-stat-price")).toContainText("999");
    await expect(page.getByTestId("market-source")).toHaveText("LIVE WS");

    // A tick for a different entity must never change the selected price.
    await sendFrames(request, {
      frames: [marketPriceFrame("base", OTHER_ADDRESS, 1, { source: "fomo-ws" })],
    });
    await expect(page.getByTestId("token-stat-price")).toContainText("999");
  });

  test("polling provenance is labelled honestly, never as LIVE WS", async ({ page, request }) => {
    await bootLive(page, request);
    await sendFrames(request, { frames: [marketStatusFrame("fomo-polling")] });
    await expect(page.getByTestId("market-source")).toHaveText("POLLING");
  });
});
