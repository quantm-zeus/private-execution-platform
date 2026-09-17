import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  configureSession,
  depthSnapshot,
  handoffKey,
  ohlcvSnapshot,
  randomKeyB64,
  resetServer,
  searchAndSelectToken,
  selectedEntityKey,
  sendFrames,
  serverState,
  setCommandResponse,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/**
 * Per-session realtime target binding, end to end.
 *
 * Selecting token A then B and changing the timeframe must issue the correct,
 * deduplicated encrypted `set_realtime_target`, and a stale frame for A must
 * never make B look live (exact entity-key isolation).
 */

const A = {
  chain: "base",
  address: "0x00000000000000000000000000000000000000a1",
  symbol: "AAA",
  name: "Token A",
  priceUsd: 1.25,
  marketCapUsd: 1_000_000,
  rank: 1,
};
const B = {
  chain: "base",
  address: "0x00000000000000000000000000000000000000b2",
  symbol: "BBB",
  name: "Token B",
  priceUsd: 2.5,
  marketCapUsd: 2_000_000,
  rank: 2,
};

function targetResponse(row: typeof A | typeof B) {
  return {
    result: {
      results: [row],
      token: { chain: row.chain, address: row.address, symbol: row.symbol, name: row.name },
      stats: {
        priceUsd: row.priceUsd,
        priceChange24h: 1,
        marketCapUsd: row.marketCapUsd,
        liquidityUsd: 100_000,
        volume24hUsd: 50_000,
        holders: 100,
      },
      risk: {
        score: 1,
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
}

async function bootLive(page: import("@playwright/test").Page, request: APIRequestContext) {
  await resetServer(request);
  const s2c = randomKeyB64();
  const c2s = randomKeyB64();
  await configureSession(request, s2c, c2s);
  await page.goto("/");
  await waitForWorkspace(page);
  await handoffKey(page, s2c, c2s);
  await waitForSocket(request);
}

async function targets(request: APIRequestContext) {
  const state = await serverState(request);
  return state.commands.filter((command) => command.op === "set_realtime_target");
}

test.describe("encrypted realtime target binding", () => {
  test("binds A then B, dedupes, and isolates stale A frames from B", async ({ page, request }) => {
    await bootLive(page, request);

    // ---- select A ----------------------------------------------------------
    await setCommandResponse(request, targetResponse(A));
    await searchAndSelectToken(page, "AAA", "AAA");
    await expect(page.getByTestId("selected-instrument")).toContainText("AAA");
    await expect.poll(async () => (await targets(request)).length, { timeout: 7_000 }).toBe(1);
    expect((await targets(request))[0]!.payload).toMatchObject({
      chain: "base",
      address: A.address,
      timeframe: "1m",
    });

    // ---- select B ----------------------------------------------------------
    await setCommandResponse(request, targetResponse(B));
    await searchAndSelectToken(page, "BBB", "BBB");
    await expect(page.getByTestId("selected-instrument")).toContainText("BBB");
    await expect.poll(async () => (await targets(request)).length, { timeout: 7_000 }).toBe(2);
    expect((await targets(request))[1]!.payload).toMatchObject({
      chain: "base",
      address: B.address,
      timeframe: "1m",
    });

    // ---- a stale A frame must not make B live ------------------------------
    await sendFrames(request, {
      frames: [ohlcvSnapshot(100, 40, { entityKey: selectedEntityKey("base", A.address) })],
    });
    await page.waitForTimeout(250);
    await expect(page.getByTestId("chart-target")).toContainText("AWAITING FEED");
    expect(await page.getByTestId("chart-target").getAttribute("data-candles")).toBe("0");

    // ---- the matching B frame makes B live ---------------------------------
    await sendFrames(request, {
      frames: [
        ohlcvSnapshot(200, 40, { entityKey: selectedEntityKey("base", B.address) }),
        depthSnapshot(200, 201),
      ],
    });
    await expect(page.getByTestId("chart-target")).toContainText("LOCAL DATA");
    const candles = Number(await page.getByTestId("chart-target").getAttribute("data-candles"));
    expect(candles).toBeGreaterThan(1);

    // ---- timeframe change issues exactly one more target -------------------
    await page.getByLabel("Chart timeframe").selectOption("15m");
    await expect.poll(async () => (await targets(request)).length, { timeout: 7_000 }).toBe(3);
    expect((await targets(request))[2]!.payload).toMatchObject({
      chain: "base",
      address: B.address,
      timeframe: "15m",
    });

    // Re-selecting the same timeframe is deduplicated.
    await page.getByLabel("Chart timeframe").selectOption("15m");
    await page.waitForTimeout(200);
    expect((await targets(request)).length).toBe(3);
  });
});
