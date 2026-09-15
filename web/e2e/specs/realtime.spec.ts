import { expect, test } from "@playwright/test";
import {
  KID,
  configureSession,
  depthSnapshot,
  handoffKey,
  ohlcvDelta,
  ohlcvSnapshot,
  randomKeyB64,
  resetServer,
  sendFrames,
  serverState,
  waitForResyncIncrease,
  waitForSocket,
  waitForWorkspace,
} from "./helpers";

/**
 * Real-browser verification of the encrypted realtime pipeline: a WebSocket
 * carries generic AEAD envelopes that the Web Worker decrypts, sequences and
 * batches before the main thread renders them on Canvas / depth tables.
 */

async function bootLive(page: import("@playwright/test").Page, request: import("@playwright/test").APIRequestContext) {
  await resetServer(request);
  const s2c = randomKeyB64();
  const c2s = randomKeyB64();
  await configureSession(request, s2c, c2s);
  await page.goto("/");
  await waitForWorkspace(page);
  await handoffKey(page, s2c, c2s);
  await waitForSocket(request);
  return { s2c, c2s };
}

test.describe("encrypted realtime workspace", () => {
  test("renders the local chart and depth from authenticated encrypted frames", async ({ page, request }) => {
    await bootLive(page, request);
    await sendFrames(request, { frames: [ohlcvSnapshot(100), depthSnapshot(100, 101)] });

    await page.locator('button[data-view="terminal"]').click();
    await expect(page.getByText("LOCAL DATA")).toBeVisible();
    await expect(page.locator(".depth-list__row").first()).toBeVisible();
    await expect(page.getByText("LIVE", { exact: true })).toBeVisible();
    // The worker owns the socket/key; the main thread only renders.
    await expect(page.getByText("worker").first()).toBeVisible();
    // No cleartext control frame may ever be sent on the binary-only relay: the
    // mock edge records (and would close on) any text frame. The worker's one
    // binary AEAD `subscribe` frame is expected and is not a text frame.
    const state = await serverState(request);
    expect(
      state.events.filter((event) => (event as { type?: string }).type === "socket-text-frame"),
    ).toHaveLength(0);
  });

  test("rejects a replayed envelope without advancing or re-rendering", async ({ page, request }) => {
    await bootLive(page, request);
    await sendFrames(request, { frames: [ohlcvSnapshot(100), depthSnapshot(100, 101)] });
    await page.locator('button[data-view="terminal"]').click();
    await expect(page.getByText("LOCAL DATA")).toBeVisible();

    const before = await serverState(request);
    await sendFrames(request, { replay: true });
    await page.waitForTimeout(300);
    const after = await serverState(request);
    // A duplicate is ignored: no resync and no new frame is applied.
    expect(after.resyncCount).toBe(before.resyncCount);
    await expect(page.getByText("LOCAL DATA")).toBeVisible();
  });

  test("recovers to live by accepting an authenticated snapshot after a sequence gap", async ({ page, request }) => {
    await bootLive(page, request);
    await sendFrames(request, { frames: [ohlcvSnapshot(100), depthSnapshot(100, 101)] });
    await page.locator('button[data-view="terminal"]').click();
    await expect(page.getByText("LOCAL DATA")).toBeVisible();

    const before = (await serverState(request)).resyncCount;
    await sendFrames(request, { skip: 3, frames: [ohlcvDelta(500)] });
    await waitForResyncIncrease(request, before);

    // The recovery snapshot must be accepted (this was a deadlock before the fix).
    await sendFrames(request, { frames: [ohlcvSnapshot(200), depthSnapshot(777, 778)] });
    await expect(page.locator(".depth-list__row").first()).toContainText("777");
    await expect(page.getByText("LIVE", { exact: true })).toBeVisible();
  });

  test("fails a tampered frame closed and recovers on a fresh authenticated snapshot", async ({ page, request }) => {
    await bootLive(page, request);
    await sendFrames(request, { frames: [ohlcvSnapshot(100), depthSnapshot(100, 101)] });
    await page.locator('button[data-view="terminal"]').click();
    await expect(page.getByText("LOCAL DATA")).toBeVisible();

    const before = (await serverState(request)).resyncCount;
    await sendFrames(request, { frames: [ohlcvDelta(500)], tamper: true });
    await waitForResyncIncrease(request, before);

    await sendFrames(request, { frames: [depthSnapshot(313, 314)] });
    await expect(page.locator(".depth-list__row").first()).toContainText("313");
    await expect(page.getByText("LIVE", { exact: true })).toBeVisible();
  });

  test("reconnects after a dropped socket and resyncs from a fresh snapshot", async ({ page, request }) => {
    await bootLive(page, request);
    await sendFrames(request, { frames: [ohlcvSnapshot(100), depthSnapshot(100, 101)] });
    await page.locator('button[data-view="terminal"]').click();
    await expect(page.getByText("LOCAL DATA")).toBeVisible();

    const before = await serverState(request);
    const resyncs = (await serverState(request)).resyncCount;
    await request.post("/__test__/close-sockets");
    await expect
      .poll(async () => (await serverState(request)).socketCount, { timeout: 10_000 })
      .toBeGreaterThan(before.socketCount);
    await waitForResyncIncrease(request, resyncs);
    await sendFrames(request, { frames: [depthSnapshot(555, 556)] });
    await expect(page.locator(".depth-list__row").first()).toContainText("555");
  });

  test("stays offline with a reason when the session key handoff is absent", async ({ page, request }) => {
    await resetServer(request);
    await page.goto("/");
    await waitForWorkspace(page);
    // No key is delivered: bootstrap itself fails closed (it can no longer fall
    // back to a cleartext probe), so the feed must never fabricate "live".
    await expect(page.getByText(/session key.*unavailable/i).first()).toBeVisible({ timeout: 6_000 });
    await expect(page.getByText("LOCAL DATA")).toHaveCount(0);
  });
});

test.describe("encrypted command channel", () => {
  test("round-trips an encrypted command and renders the decrypted result", async ({ page, request }) => {
    await resetServer(request);
    const s2c = randomKeyB64();
    const c2s = randomKeyB64();
    await configureSession(request, s2c, c2s);
    await request.post("/__test__/command-response", {
      data: {
        response: {
          result: {
            results: [
              { chain: "base", address: "0xBONKtokenAddress000000000000000000000000", symbol: "BONK" },
            ],
          },
        },
      },
    });

    await page.goto("/");
    await waitForWorkspace(page);
    await handoffKey(page, s2c, c2s);
    await waitForSocket(request);

    await page.locator('button[data-view="discover"]').click();
    await page.getByLabel("Search token").fill("bonk");
    await page.getByRole("button", { name: "Search" }).click();

    await expect(page.locator(".search-results__symbol")).toHaveText("BONK");
    const state = await serverState(request);
    const search = state.commands.find((command) => command.op === "search_token");
    expect(search).toBeTruthy();
    expect(search?.payload).toMatchObject({ query: "bonk" });
  });

  test("never emits an operation type or payload in the cleartext envelope", async ({ page, request }) => {
    await resetServer(request);
    const s2c = randomKeyB64();
    const c2s = randomKeyB64();
    const cleartextBodies: string[] = [];
    page.on("request", (outgoing) => {
      if (outgoing.url().endsWith("/v1/command") && outgoing.method() === "POST") {
        // The request is an octet-stream envelope; postData() only exposes text
        // bodies, so read the raw buffer and decode it as UTF-8 JSON.
        const buffer = outgoing.postDataBuffer();
        if (buffer) cleartextBodies.push(buffer.toString("utf8"));
      }
    });
    await configureSession(request, s2c, c2s);
    await request.post("/__test__/command-response", {
      data: { response: { result: { results: [] } } },
    });
    await page.goto("/");
    await waitForWorkspace(page);
    await handoffKey(page, s2c, c2s);
    await waitForSocket(request);

    await page.locator('button[data-view="discover"]').click();
    await page.getByLabel("Search token").fill("secretquery");
    await page.getByRole("button", { name: "Search" }).click();
    await expect.poll(() => cleartextBodies.length, { timeout: 7_000 }).toBeGreaterThan(0);

    for (const body of cleartextBodies) {
      expect(body).not.toContain("search_token");
      expect(body).not.toContain("secretquery");
      const parsed = JSON.parse(body) as Record<string, unknown>;
      expect(Object.keys(parsed).sort()).toEqual(["ciphertext", "kid", "nonce", "sequence"]);
      expect(parsed.kid).toBe(KID);
    }
  });
});
