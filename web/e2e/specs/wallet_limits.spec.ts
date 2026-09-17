import { expect, test } from "@playwright/test";
import {
  configureSession,
  handoffKey,
  randomKeyB64,
  resetServer,
  serverState,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/**
 * W14 in a real browser: the on-demand security drawer exposes the
 * trading-wallet limit configuration. The mock applies a write and changes the
 * authoritative read, so the test proves the full load → tighten → verify →
 * relax (phrase-gated) flow. The write travels only to the neutral first-party
 * `set_wallet_limits` command.
 */

test.describe("trading wallet limits (W14)", () => {
  test("loads the policy, saves a tightening, and gates a relaxation behind the phrase", async ({
    page,
    request,
  }) => {
    await resetServer(request);
    const s2c = randomKeyB64();
    const c2s = randomKeyB64();
    await configureSession(request, s2c, c2s);

    await page.goto("/");
    await waitForWorkspace(page);
    await handoffKey(page, s2c, c2s);
    await waitForSocket(request);

    // Security & settings moved to the on-demand drawer opened from the top bar.
    await page.getByRole("button", { name: "Security and settings" }).click();
    await expect(page.getByRole("dialog", { name: "Security and settings" })).toBeVisible();
    const maxTrade = page.getByTestId("limit-maxTradeUsd");
    await expect(maxTrade).toHaveValue("5000");

    // A tightening saves with no extra confirmation and is verified against the
    // authoritative re-read.
    await maxTrade.fill("1000");
    const save = page.getByRole("button", { name: "Save limits" });
    await expect(save).toBeEnabled();
    await save.click();
    await expect
      .poll(async () => {
        const state = await serverState(request);
        return state.commands.filter((command) => command.op === "set_wallet_limits").length;
      })
      .toBe(1);
    const first = await serverState(request);
    expect(first.commands.find((command) => command.op === "set_wallet_limits")?.payload).toMatchObject(
      { max_trade_usd: 1_000 },
    );
    await expect(page.getByText(/verified against the authoritative policy/i)).toBeVisible();
    await expect(maxTrade).toHaveValue("1000");

    // A relaxation is refused until the exact phrase is entered.
    await maxTrade.fill("9000");
    await expect(save).toBeDisabled();
    await expect(page.getByText(/relaxes a safety limit/i)).toBeVisible();
    await page.getByLabel("Limit change confirmation phrase").fill("CONFIRM LIMIT CHANGE");
    await expect(save).toBeEnabled();

    // The relaxation confirmation is a security-critical surface: gate it at
    // moderate-or-worse (WCAG 2.2 AA), not only serious/critical.
    await page.addScriptTag({ url: "/__test__/axe.min.js" });
    const confirmViolations = await page.evaluate(async () => {
      const axe = (window as unknown as { axe: { run: (ctx: Document, opts: unknown) => Promise<{ violations: { id: string; impact: string; nodes: { target: string[] }[] }[] }> } }).axe;
      const result = await axe.run(document, { resultTypes: ["violations"] });
      return result.violations
        .filter((violation) => ["moderate", "serious", "critical"].includes(violation.impact))
        .map((violation) => ({
          id: violation.id,
          impact: violation.impact,
          nodes: violation.nodes.map((node) => node.target),
        }));
    });
    expect(confirmViolations, JSON.stringify(confirmViolations, null, 2)).toEqual([]);

    await save.click();
    await expect
      .poll(async () => {
        const after = await serverState(request);
        return after.commands.filter((command) => command.op === "set_wallet_limits").length;
      })
      .toBe(2);
    const second = await serverState(request);
    const writes = second.commands.filter((command) => command.op === "set_wallet_limits");
    expect(writes.at(-1)?.payload).toMatchObject({ max_trade_usd: 9_000 });
    await expect(page.getByText(/verified against the authoritative policy/i)).toBeVisible();
    await expect(maxTrade).toHaveValue("9000");
  });
});
