import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import {
  configureSession,
  depthSnapshot,
  handoffKey,
  ohlcvSnapshot,
  randomKeyB64,
  resetServer,
  searchTokens,
  sendFrames,
  serverState,
  setCommandResponse,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/** A search + detail body so the ticket panes can be driven in the axe scan. */
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

interface AxeViolation {
  id: string;
  impact: string;
  nodes: number;
  samples: { target: string[]; html: string; summary?: string }[];
}

async function collectAxeViolations(page: Page): Promise<AxeViolation[]> {
  return page.evaluate(async () => {
    interface AxeNode {
      target: string[];
      html: string;
      failureSummary?: string;
    }
    interface AxeResult {
      id: string;
      impact: string;
      nodes: AxeNode[];
    }
    const axe = (
      window as unknown as {
        axe: { run: (ctx: Document, opts: unknown) => Promise<{ violations: AxeResult[] }> };
      }
    ).axe;
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
}

function moderateOrWorse(violations: AxeViolation[]): AxeViolation[] {
  return violations.filter((violation) =>
    ["moderate", "serious", "critical"].includes(violation.impact),
  );
}

test.describe("accessibility", () => {
  test("has no serious/critical axe violations across workstation states", async ({ page, request }) => {
    await bootLive(page, request);
    await page.addScriptTag({ url: "/__test__/axe.min.js" });

    const failures: unknown[] = [];
    const scan = async (state: string): Promise<void> => {
      await page.waitForTimeout(60);
      for (const violation of await collectAxeViolations(page)) {
        if (violation.impact === "serious" || violation.impact === "critical") {
          failures.push({ state, ...violation });
        }
      }
    };

    await scan("no token selected");

    await setCommandResponse(request, TARGET_RESPONSE);
    await searchTokens(page, "SOL");
    await expect(page.locator(".search-popover .search-results__symbol").first()).toBeVisible();
    await scan("search results");

    await page.locator(".search-popover .search-results__symbol").first().click();
    await expect(page.getByTestId("selected-instrument")).toContainText("SOL");
    await scan("market ticket");

    await page.getByTestId("ticket-tab-limit").click();
    await scan("limit ticket");
    await page.getByTestId("ticket-tab-market").click();

    for (const tab of ["positions", "orders", "activity", "trades", "holders"] as const) {
      await page.getByTestId(`dock-tab-${tab}`).click();
      await scan(`dock ${tab}`);
    }

    await page.getByRole("button", { name: "Security and settings" }).click();
    await expect(page.getByRole("dialog", { name: "Security and settings" })).toBeVisible();
    await scan("security drawer");

    expect(failures, JSON.stringify(failures, null, 2)).toEqual([]);
  });

  // Security and confirmation surfaces gate at moderate-or-worse: a moderate
  // accessibility defect on a kill-switch/recovery control is release-relevant
  // even when it is not "serious".
  test("security drawer has no moderate-or-worse axe violations", async ({ page, request }) => {
    await bootLive(page, request);
    await page.addScriptTag({ url: "/__test__/axe.min.js" });
    await page.getByRole("button", { name: "Security and settings" }).click();
    await expect(page.getByRole("dialog", { name: "Security and settings" })).toBeVisible();
    await page.waitForTimeout(60);
    const violations = moderateOrWorse(await collectAxeViolations(page));
    expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
  });

  test("withdrawal confirmation has no moderate-or-worse axe violations", async ({
    page,
    request,
  }) => {
    await bootLive(page, request);
    await page.getByRole("button", { name: "Security and settings" }).click();
    await page.getByLabel("Destination address").fill("0x1234567890abcdef");
    await page.getByLabel("Withdrawal amount").fill("1.5");
    await page.getByRole("button", { name: "Review withdrawal" }).click();
    // The irreversible-action review is a security-critical confirmation surface.
    await expect(page.getByRole("alertdialog", { name: "Confirm withdrawal" })).toBeVisible();
    await page.addScriptTag({ url: "/__test__/axe.min.js" });
    const violations = moderateOrWorse(await collectAxeViolations(page));
    expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
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
    await expect(page.getByTestId("trading-gate")).toHaveText("TRADING ENABLED");
    const loadMs = Date.now() - startedAt;
    // eslint-disable-next-line no-console
    console.log(`[perf] post-auth workspace load: ${loadMs}ms`);
    expect(loadMs).toBeLessThan(2_000);
  });

  test("applies a realtime frame to the DOM under the 300ms visual budget", async ({ page, request }) => {
    await bootLive(page, request);
    // The chart pane is always mounted; live data needs no view navigation.
    await expect(page.getByTestId("chart-target").getByText("LOCAL DATA")).toBeVisible();

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

    // The top-bar search debounces 300ms before dispatching, so the measured
    // `/v1/command` fetch stays the actual encrypted round trip.
    await searchTokens(page, "bonk");
    await expect
      .poll(
        () => page.evaluate(() => (window as unknown as { __commandMs: number[] }).__commandMs.length),
        { timeout: 7_000 },
      )
      .toBeGreaterThan(0);

    // Bind the measurement to the search action: the test server only records a
    // command `op` after it decrypts the envelope, so an unrelated `/v1/command`
    // call can no longer satisfy the round-trip assertion.
    await expect
      .poll(async () => (await serverState(request)).commands.map((command) => command.op), {
        timeout: 7_000,
      })
      .toContain("search_token");

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
  test("has no horizontal overflow at 390px across workstation states", async ({ page, request }) => {
    await bootLive(page, request);
    await page.setViewportSize({ width: 390, height: 844 });

    const states: { name: string; apply: () => Promise<void> }[] = [
      { name: "workstation", apply: async () => {} },
      {
        name: "open orders dock",
        apply: async () => {
          await page.getByTestId("dock-tab-orders").click();
        },
      },
      {
        name: "activity dock",
        apply: async () => {
          await page.getByTestId("dock-tab-activity").click();
        },
      },
      {
        name: "trade ticket open",
        apply: async () => {
          const toggle = page.getByLabel("Toggle trade ticket");
          await expect(toggle).toBeVisible();
          await toggle.click();
          await expect(page.locator(".terminal.workspace")).toHaveAttribute("data-ticket", "open");
        },
      },
      {
        name: "security drawer",
        apply: async () => {
          await page.getByRole("button", { name: "Security and settings" }).click();
          await expect(page.getByRole("dialog", { name: "Security and settings" })).toBeVisible();
        },
      },
    ];

    for (const state of states) {
      await state.apply();
      await page.waitForTimeout(40);
      const overflow = await page.evaluate(() => ({
        doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        body: document.body.scrollWidth - document.body.clientWidth,
      }));
      // Allow a 1px sub-pixel tolerance; a real layout overflow is far larger.
      expect(overflow.doc, `${state.name}: document overflow ${overflow.doc}px`).toBeLessThanOrEqual(1);
      expect(overflow.body, `${state.name}: body overflow ${overflow.body}px`).toBeLessThanOrEqual(1);
    }
  });
});
