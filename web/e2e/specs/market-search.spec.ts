import { expect, test } from "@playwright/test";
import {
  configureSession,
  handoffKey,
  randomKeyB64,
  resetServer,
  searchTokens,
  serverState,
  setCommandResponse,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/**
 * Global search regression: symbol, name and full address queries are forwarded
 * to the encrypted `search_token` contract unchanged, and the result row shows
 * symbol + name + chain + compact address with the price as the market value.
 */

const ADDRESS = "0x00000000000000000000000000000000000000a1";
const RESPONSE = {
  result: {
    results: [
      {
        chain: "base",
        address: ADDRESS,
        symbol: "SOL",
        name: "Wrapped SOL",
        priceUsd: 150.25,
        marketCapUsd: 68_000_000,
        rank: 4,
      },
    ],
  },
};

test.describe("global token search semantics", () => {
  test("forwards name and address queries unchanged and renders the market row", async ({
    page,
    request,
  }) => {
    await resetServer(request);
    const s2c = randomKeyB64();
    const c2s = randomKeyB64();
    await configureSession(request, s2c, c2s);
    await setCommandResponse(request, RESPONSE);

    await page.goto("/");
    await waitForWorkspace(page);
    await handoffKey(page, s2c, c2s);
    await waitForSocket(request);

    // ---- by name -----------------------------------------------------------
    await searchTokens(page, "Wrapped SOL");
    const option = page.locator('.search-popover [role="option"]').first();
    await expect(option).toBeVisible();
    await expect(option.locator(".search-results__symbol")).toHaveText("SOL");
    await expect(option).toContainText("Wrapped SOL");
    await expect(option).toContainText("base");
    await expect(option.locator(".search-results__address")).toContainText("0x00");
    await expect(option.locator('[data-testid="search-result-price"]')).toContainText("$150.25");

    // The listbox must escape the 46px top bar rather than being clipped to it,
    // and the option must be the topmost element at its own centre (a bounding
    // box alone does not reveal ancestor overflow clipping).
    const popoverBox = await page.locator(".search-popover").boundingBox();
    const topbarBox = await page.getByTestId("terminal-topbar").boundingBox();
    expect(popoverBox, "popover box").not.toBeNull();
    expect(popoverBox!.width, "popover has menu width").toBeGreaterThan(120);
    expect(topbarBox, "topbar box").not.toBeNull();
    const optionBox = await option.boundingBox();
    expect(optionBox, "option box").not.toBeNull();
    expect(optionBox!.y, "option below the topbar").toBeGreaterThan(
      topbarBox!.y + topbarBox!.height - 1,
    );
    const hit = await page.evaluate(
      ({ x, y }) => {
        const el = document.elementFromPoint(x, y);
        return el && el.closest('[role="option"]') ? "option" : (el?.tagName ?? "none");
      },
      { x: optionBox!.x + optionBox!.width / 2, y: optionBox!.y + optionBox!.height / 2 },
    );
    expect(hit, "option is the topmost element (not clipped by the topbar)").toBe("option");

    await expect
      .poll(async () => {
        const state = await serverState(request);
        return state.commands
          .filter((command) => command.op === "search_token")
          .map((command) => (command.payload as { query?: string }).query);
      })
      .toContain("Wrapped SOL");

    // ---- by full address ---------------------------------------------------
    await searchTokens(page, ADDRESS);
    await expect
      .poll(async () => {
        const state = await serverState(request);
        return state.commands
          .filter((command) => command.op === "search_token")
          .map((command) => (command.payload as { query?: string }).query);
      })
      .toContain(ADDRESS);
  });
});
