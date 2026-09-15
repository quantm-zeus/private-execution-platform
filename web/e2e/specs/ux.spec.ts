import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import {
  configureSession,
  depthSnapshot,
  handoffKey,
  ohlcvSnapshot,
  randomKeyB64,
  resetServer,
  sendFrames,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

const VIEWS = [
  "overview",
  "discover",
  "terminal",
  "trade",
  "limits",
  "execution",
  "portfolio",
  "intelligence",
  "security",
] as const;

async function bootLive(page: Page, request: APIRequestContext) {
  await resetServer(request);
  const s2c = randomKeyB64();
  const c2s = randomKeyB64();
  await configureSession(request, s2c, c2s);
  await page.goto("/");
  await waitForWorkspace(page);
  await handoffKey(page, s2c, c2s);
  await waitForSocket(request);
  await sendFrames(request, { frames: [ohlcvSnapshot(100), depthSnapshot(100, 101)] });
  return { s2c, c2s };
}

test.describe("accessibility", () => {
  test("has no serious/critical axe violations on any view", async ({ page, request }) => {
    await bootLive(page, request);
    await page.addScriptTag({ url: "/__test__/axe.min.js" });

    const failures: unknown[] = [];
    for (const view of VIEWS) {
      await page.locator(`button[data-view="${view}"]`).click();
      await page.waitForTimeout(60);
      const violations = await page.evaluate(async () => {
        const axe = (window as unknown as { axe: { run: (ctx: Document, opts: unknown) => Promise<{ violations: { id: string; impact: string; nodes: { target: string[]; failureSummary?: string; html: string }[] }[] }> } }).axe;
        const result = await axe.run(document, { resultTypes: ["violations"] });
        return result.violations.map((violation) => ({
          id: violation.id,
          impact: violation.impact,
          nodes: violation.nodes.length,
          samples: violation.nodes.slice(0, 3).map((node) => ({
            target: node.target,
            html: node.html,
            summary: node.failureSummary,
          })),
        }));
      });
      for (const violation of violations) {
        if (violation.impact === "serious" || violation.impact === "critical") {
          failures.push({ view, ...violation });
        }
      }
    }
    expect(failures, JSON.stringify(failures, null, 2)).toEqual([]);
  });

  // Security and confirmation surfaces gate at moderate-or-worse: a moderate
  // accessibility defect on a kill-switch/recovery control is release-relevant
  // even when it is not "serious".
  test("security view has no moderate-or-worse axe violations", async ({ page, request }) => {
    await bootLive(page, request);
    await page.addScriptTag({ url: "/__test__/axe.min.js" });
    await page.locator('button[data-view="security"]').click();
    await page.waitForTimeout(60);
    const violations = await page.evaluate(async () => {
      const axe = (window as unknown as { axe: { run: (ctx: Document, opts: unknown) => Promise<{ violations: { id: string; impact: string; nodes: { target: string[]; failureSummary?: string; html: string }[] }[] }> } }).axe;
      const result = await axe.run(document, { resultTypes: ["violations"] });
      return result.violations.map((violation) => ({
        id: violation.id,
        impact: violation.impact,
        nodes: violation.nodes.length,
        samples: violation.nodes.slice(0, 3).map((node) => ({
          target: node.target,
          html: node.html,
          summary: node.failureSummary,
        })),
      }));
    });
    const moderate = violations.filter((violation) =>
      ["moderate", "serious", "critical"].includes(violation.impact),
    );
    expect(moderate, JSON.stringify(moderate, null, 2)).toEqual([]);
  });
});

test.describe("performance budgets (local harness)", () => {
  test("post-auth workspace load stays under the 2s budget", async ({ page, request }) => {
    await resetServer(request);
    const s2c = randomKeyB64();
    const c2s = randomKeyB64();
    await configureSession(request, s2c, c2s);
    const startedAt = Date.now();
    await page.goto("/");
    // Opaque bootstrap needs the BR-5 handoff before it can resolve.
    await handoffKey(page, s2c, c2s);
    await expect(page.getByText("TRADING ENABLED")).toBeVisible();
    const loadMs = Date.now() - startedAt;
    // eslint-disable-next-line no-console
    console.log(`[perf] post-auth workspace load: ${loadMs}ms`);
    expect(loadMs).toBeLessThan(2_000);
  });

  test("applies a realtime frame to the DOM under the 300ms visual budget", async ({ page, request }) => {
    await bootLive(page, request);
    await page.locator('button[data-view="terminal"]').click();
    await expect(page.getByText("LOCAL DATA")).toBeVisible();

    await page.evaluate(() => {
      (window as unknown as { __frameT0: number }).__frameT0 = performance.now();
    });
    await sendFrames(request, { frames: [depthSnapshot(424, 425)] });
    await expect(page.locator(".depth-list__row").first()).toContainText("424");
    const updateMs = await page.evaluate(
      () => performance.now() - (window as unknown as { __frameT0: number }).__frameT0,
    );
    // eslint-disable-next-line no-console
    console.log(`[perf] visual update: ${updateMs.toFixed(1)}ms`);
    expect(updateMs).toBeLessThan(300);
  });

  test("processes a UI command round trip under the 100ms local budget", async ({ page, request }) => {
    await resetServer(request);
    const s2c = randomKeyB64();
    const c2s = randomKeyB64();
    await configureSession(request, s2c, c2s);
    await request.post("/__test__/command-response", {
      data: { response: { result: { results: [] } } },
    });
    await page.goto("/");
    await waitForWorkspace(page);
    await handoffKey(page, s2c, c2s);
    await waitForSocket(request);

    await page.evaluate(() => {
      const original = window.fetch.bind(window);
      (window as unknown as { __commandMs: number[] }).__commandMs = [];
      window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        const t0 = performance.now();
        const response = await original(input, init);
        if (String(input).includes("/v1/command")) {
          (window as unknown as { __commandMs: number[] }).__commandMs.push(performance.now() - t0);
        }
        return response;
      };
    });

    await page.locator('button[data-view="discover"]').click();
    await page.getByLabel("Search token").fill("bonk");
    await page.getByRole("button", { name: "Search" }).click();
    await expect
      .poll(
        () => page.evaluate(() => (window as unknown as { __commandMs: number[] }).__commandMs.length),
        { timeout: 7_000 },
      )
      .toBeGreaterThan(0);

    const samples = await page.evaluate(
      () => (window as unknown as { __commandMs: number[] }).__commandMs,
    );
    const worst = Math.max(...samples);
    // eslint-disable-next-line no-console
    console.log(`[perf] command round trip: ${worst.toFixed(1)}ms`);
    expect(worst).toBeLessThan(100);
  });
});

test.describe("responsive layout (AC1.2)", () => {
  test("has no horizontal overflow at 390px on every view", async ({ page, request }) => {
    await bootLive(page, request);
    await page.setViewportSize({ width: 390, height: 844 });
    for (const view of VIEWS) {
      await page.locator(`button[data-view="${view}"]`).click();
      await page.waitForTimeout(40);
      const overflow = await page.evaluate(() => ({
        doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        body: document.body.scrollWidth - document.body.clientWidth,
      }));
      // Allow a 1px sub-pixel tolerance; a real layout overflow is far larger.
      expect(overflow.doc, `${view}: document overflow ${overflow.doc}px`).toBeLessThanOrEqual(1);
      expect(overflow.body, `${view}: body overflow ${overflow.body}px`).toBeLessThanOrEqual(1);
    }
  });
});
