import { expect, test } from "@playwright/test";
import { configureSession, handoffKey, randomKeyB64, resetServer, waitForWorkspace } from "./helpers";

const ALL_TRUE_BOOTSTRAP = {
  protocol_version: 1,
  capabilities: {
    market: true,
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

test.describe("fail-closed private workspace", () => {
  test("renders an explicit unavailable state and enables no capability on 404", async ({ page }) => {
    await page.route("**/v1/bootstrap", (route) => route.fulfill({ status: 404, body: "not found" }));
    await page.goto("/");
    // Bootstrap is opaque now: it needs a BR-5 key before the routed 404 can be
    // observed (with no key it fails closed locally instead of probing).
    await handoffKey(page, randomKeyB64(), randomKeyB64());

    await expect(page.locator(".workspace")).toBeVisible();
    await expect(page.getByText(/not available on this deployment/i).first()).toBeVisible();
    await expect(page.locator(".chip--on")).toHaveCount(0);
    await expect(page.getByText("TRADING ENABLED")).toHaveCount(0);
  });

  test("maps an unauthorized bootstrap to an auth error, never a ready state", async ({ page }) => {
    await page.route("**/v1/bootstrap", (route) => route.fulfill({ status: 401, body: "no" }));
    await page.goto("/");
    await handoffKey(page, randomKeyB64(), randomKeyB64());

    await expect(page.getByText(/not authorized/i).first()).toBeVisible();
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
    await page.goto("/");
    await waitForWorkspace(page);
    await handoffKey(page, s2c, c2s);
    await expect(page.locator(".workspace")).toBeVisible();
    await expect(page.getByText(/trading is disabled|foundation phase/i).first()).toBeVisible();

    await page.locator('button[data-view="trade"]').click();
    // Retained (previously visited) views stay mounted but hidden; scope the
    // assertion to the active view so a hidden Overview hint cannot satisfy it.
    const activeView = page.locator(".view-slot:not(.view-slot--hidden)");
    await expect(
      activeView.getByText(/trading is disabled|foundation phase/i).first(),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: /execute buy/i })).toBeDisabled();

    await page.locator('button[data-view="limits"]').click();
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
    await expect(page.locator(".workspace")).toBeVisible();
    await page.locator('button[data-view="terminal"]').click();

    await expect(page.getByText("AWAITING FEED")).toBeVisible();
    await expect(page.locator(".depth-list__row")).toHaveCount(0);
    await expect(page.getByText(/no depth/i).first()).toBeVisible();
  });
});
