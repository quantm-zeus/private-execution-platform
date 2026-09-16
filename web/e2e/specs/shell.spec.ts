import { expect, test } from "@playwright/test";

const SHELL_ORIGIN = `http://127.0.0.1:${process.env.E2E_SHELL_PORT ?? 4320}`;
const ALLOW_SKIP = process.env.E2E_ALLOW_SKIP === "1";

async function unlockInfo(request: import("@playwright/test").APIRequestContext) {
  const response = await request.get(`${SHELL_ORIGIN}/__test__/unlock`);
  return (await response.json()) as {
    available: boolean;
    reason?: string;
    secretB64?: string;
    kidB64?: string;
  };
}

/**
 * The unlock boundary is the security-critical path this suite exists to prove.
 * If the HPKE/artifact tooling is missing it must FAIL the run, not silently
 * skip: a green CI with the boundary untested is worse than a red CI.
 * `E2E_ALLOW_SKIP=1` is a local-only opt-out.
 */
test.beforeAll(async () => {
  let info: { available: boolean; reason?: string };
  try {
    const response = await fetch(`${SHELL_ORIGIN}/__test__/unlock`);
    info = (await response.json()) as { available: boolean; reason?: string };
  } catch (error) {
    throw new Error(
      `shell-unlock host not reachable at ${SHELL_ORIGIN}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!info.available && !ALLOW_SKIP) {
    throw new Error(
      `shell-unlock crypto tooling unavailable: ${info.reason ?? "unknown"}. ` +
        "Build it with `cargo build -p crypto-envelope --bins --example test-session-host` " +
        "(or set E2E_CRYPTO_TARGET). Set E2E_ALLOW_SKIP=1 only for local runs without tooling.",
    );
  }
});

async function unlock(page: import("@playwright/test").Page, info: { secretB64?: string; kidB64?: string }) {
  await page.goto(`${SHELL_ORIGIN}/`);
  // The host reports an existing operator session, so the descriptor loads
  // automatically and only the offline recovery code is required. The KID is
  // never typed: it comes from the authenticated descriptor.
  await page.locator("#recovery-code").fill(info.secretB64!);
  // Snapshot the field at the instant the first unlock network exchange starts.
  // `toHaveValue("")` below retries for up to 7s, so on its own it would also
  // pass if the secret were cleared only after the exchange; this route pins the
  // "cleared before the first await" claim. The grant request always fires on an
  // unlock (enrollment may be skipped once the host has bound the key).
  let valueAtFirstGrant: string | null = null;
  // Resolved by the first intercepted grant request. `page.route` handlers run
  // asynchronously, so reading `valueAtFirstGrant` straight after the clear
  // assertion can observe `null` before the grant route has fired; awaiting this
  // promise makes the observation deterministic without weakening the DOM-clear
  // security assertion below.
  let resolveFirstGrant: () => void = () => {};
  const firstGrantSeen = new Promise<void>((resolve) => {
    resolveFirstGrant = resolve;
  });
  await page.route("**/internal/artifact/grant", async (route) => {
    if (valueAtFirstGrant === null) {
      valueAtFirstGrant = await page.locator("#recovery-code").inputValue();
      resolveFirstGrant();
    }
    await route.continue();
  });
  await page.getByRole("button", { name: "Unlock Workspace" }).click();
  // The recovery code is cleared from the DOM synchronously before the first
  // network await, and the form stays mounted until the payload boots, so this
  // pins the secret-lifetime claim.
  await expect(page.locator("#recovery-code")).toHaveValue("");
  await firstGrantSeen;
  expect(valueAtFirstGrant).toBe("");
  // The payload may announce readiness and overwrite the status text, so wait for
  // the instantiated frame itself rather than a transient status string.
  await expect(page.locator("#workspace-frame")).toBeVisible({ timeout: 20_000 });
}

/**
 * Exercises the real authenticated-unlock boundary: the shell derives the
 * workspace key in audited WASM, HPKE-unwraps the encrypted artifact, and
 * instantiates the decrypted payload from `blob:` URLs inside a
 * `sandbox="allow-scripts allow-same-origin"` frame under the production CSP.
 */
test.describe("shell artifact unlock", () => {
  test("decrypts the artifact in memory and boots the private payload", async ({ page, request }) => {
    const info = await unlockInfo(request);
    test.skip(!info.available, `crypto tooling unavailable: ${info.reason ?? "unknown"}`);

    await unlock(page, info);

    const frame = page.frameLocator("#workspace-frame");
    // The decrypted payload must execute under the shell CSP (`blob:` allowed).
    await expect(frame.locator(".workspace")).toBeVisible({ timeout: 20_000 });
    await expect(frame.getByRole("heading", { name: /Evergreen Private Workspace/i })).toBeVisible();
    // The test host exposes no `/v1` private API, so the payload must fail closed
    // with an explicit unavailable state and never fabricate data.
    await expect(
      frame.getByText(/not available|unavailable|unreachable|not authorized/i).first(),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("lock revokes the blob payload frame and private state", async ({ page, request }) => {
    const info = await unlockInfo(request);
    test.skip(!info.available, `crypto tooling unavailable: ${info.reason ?? "unknown"}`);

    await unlock(page, info);
    await expect(page.frameLocator("#workspace-frame").locator(".workspace")).toBeVisible({
      timeout: 20_000,
    });

    await page.getByRole("button", { name: "Lock Workspace" }).click();
    await expect(page.locator("#workspace-frame")).toHaveCount(0);
    await expect(page.getByText("Workspace locked.")).toBeVisible();
  });

  test("rejects a wrong unlock secret without instantiating a payload", async ({ page, request }) => {
    const info = await unlockInfo(request);
    test.skip(!info.available, `crypto tooling unavailable: ${info.reason ?? "unknown"}`);

    await page.goto(`${SHELL_ORIGIN}/`);
    await page.locator("#recovery-code").fill(Buffer.alloc(32, 9).toString("base64"));
    await page.getByRole("button", { name: "Unlock Workspace" }).click();

    // The published release fingerprint lets the shell reject the wrong code
    // locally, before any network call, with actionable recovery guidance.
    await expect(page.locator(".notice__title")).toContainText(
      /does not match the published release/i,
      { timeout: 20_000 },
    );
    await expect(page.locator("#workspace-frame")).toHaveCount(0);
    await expect(page.locator("#recovery-code")).toHaveCount(1);
  });

  test("shows an explicit open action, never a KID field, and no passkey on mount", async ({ page }) => {
    // Count WebAuthn ceremonies so an accidental auto-authentication on mount
    // cannot hide behind a prompt the harness silently rejects.
    await page.addInitScript(() => {
      (window as unknown as { __passkeyCalls: number }).__passkeyCalls = 0;
      const container = navigator.credentials as unknown as Record<string, unknown>;
      if (!container) return;
      for (const name of ["get", "create"] as const) {
        const original = container[name];
        if (typeof original !== "function") continue;
        container[name] = function (this: unknown, ...args: unknown[]) {
          (window as unknown as { __passkeyCalls: number }).__passkeyCalls += 1;
          return (original as (...a: unknown[]) => unknown).apply(container, args);
        };
      }
    });
    // Force a signed-out operator session for this page only.
    await page.route("**/internal/auth/session", (route) =>
      route.fulfill({ status: 401, body: "" }),
    );
    await page.goto(`${SHELL_ORIGIN}/`);

    await expect(
      page.getByRole("button", { name: "Open Private Workspace" }),
    ).toBeVisible();
    // No manual Key ID anywhere in the normal flow.
    await expect(page.locator("#unlock-kid")).toHaveCount(0);
    await expect(page.locator("#kid")).toHaveCount(0);
    // The unlock form is not offered until the operator acts.
    await expect(page.locator("#recovery-code")).toHaveCount(0);
    // Bootstrap enrollment stays hidden while the server reports it closed.
    await expect(page.getByText("First-run passkey enrollment")).toHaveCount(0);
    // No passkey pop-up on mount: exactly zero ceremonies until the user acts.
    expect(
      await page.evaluate(
        () => (window as unknown as { __passkeyCalls: number }).__passkeyCalls,
      ),
    ).toBe(0);
    // Positive control: the instrumentation really records a ceremony call, so
    // the zero assertion above cannot pass vacuously.
    await page.evaluate(() => {
      try {
        (navigator.credentials.get as unknown as (options?: unknown) => unknown)(undefined);
      } catch {
        // The platform rejects the invalid request; only the counter matters.
      }
    });
    expect(
      await page.evaluate(
        () => (window as unknown as { __passkeyCalls: number }).__passkeyCalls,
      ),
    ).toBeGreaterThanOrEqual(1);
  });

  test("shows bootstrap enrollment only when the server reports it open", async ({ page }) => {
    // Positive control for the closed-state assertion above: when the server
    // actually reports first-run enrollment open, the control must appear.
    await page.route("**/internal/auth/session", (route) =>
      route.fulfill({ status: 401, body: "" }),
    );
    await page.route("**/internal/auth/enrollment-status", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ enrollment_open: true }),
      }),
    );
    await page.goto(`${SHELL_ORIGIN}/`);
    await expect(page.getByText("First-run passkey enrollment")).toBeVisible();
  });

  test("security gateway has no moderate-or-worse axe violations", async ({ page }) => {
    await page.route("**/internal/auth/session", (route) =>
      route.fulfill({ status: 401, body: "" }),
    );
    await page.goto(`${SHELL_ORIGIN}/`);
    await expect(
      page.getByRole("button", { name: "Open Private Workspace" }),
    ).toBeVisible();
    await page.addScriptTag({ url: "/__test__/axe.min.js" });
    const violations = await page.evaluate(async () => {
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
    expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
  });

  test("the authenticated unlock surface and failure alert have no moderate-or-worse axe violations", async ({
    page,
    request,
  }) => {
    const info = await unlockInfo(request);
    test.skip(!info.available, `crypto tooling unavailable: ${info.reason ?? "unknown"}`);

    const axeViolations = () =>
      page.evaluate(async () => {
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

    await page.goto(`${SHELL_ORIGIN}/`);
    // Authenticated + descriptor loaded: the unlock form, release fingerprint and
    // recovery guidance are mounted, none of which the signed-out scan covers.
    await expect(page.locator("#recovery-code")).toBeVisible({ timeout: 20_000 });
    await page.addScriptTag({ url: "/__test__/axe.min.js" });
    expect(await axeViolations(), "authenticated unlock surface").toEqual([]);

    // Trigger the credential-failure alert and scan that security-relevant state.
    await page.locator("#recovery-code").fill(Buffer.alloc(32, 9).toString("base64"));
    await page.getByRole("button", { name: "Unlock Workspace" }).click();
    await expect(page.locator(".notice__title")).toBeVisible({ timeout: 20_000 });
    expect(await axeViolations(), "credential-failure alert").toEqual([]);
  });

  test("the security gateway honours reduced motion and 44px touch targets", async ({
    page,
    request,
  }) => {
    const info = await unlockInfo(request);
    test.skip(!info.available, `crypto tooling unavailable: ${info.reason ?? "unknown"}`);
    // Mobile viewport: every primary control must still meet the 44x44 minimum.
    await page.setViewportSize({ width: 390, height: 844 });
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto(`${SHELL_ORIGIN}/`);

    const primary = page.locator("button.button--primary").first();
    await expect(primary).toBeVisible({ timeout: 20_000 });
    const buttonBox = await primary.boundingBox();
    expect(buttonBox).not.toBeNull();
    expect(buttonBox!.height).toBeGreaterThanOrEqual(44);
    expect(buttonBox!.width).toBeGreaterThanOrEqual(44);

    const input = page.locator("#recovery-code");
    await expect(input).toBeVisible();
    const inputBox = await input.boundingBox();
    expect(inputBox).not.toBeNull();
    expect(inputBox!.height).toBeGreaterThanOrEqual(44);

    // `* { transition: none !important }` under prefers-reduced-motion.
    await expect(primary).toHaveCSS("transition-duration", "0s");
  });

  test("honours a lock request from the decrypted payload", async ({ page, request }) => {
    const info = await unlockInfo(request);
    test.skip(!info.available, `crypto tooling unavailable: ${info.reason ?? "unknown"}`);

    await unlock(page, info);
    const frame = page.frameLocator("#workspace-frame");
    await expect(frame.locator(".workspace")).toBeVisible({ timeout: 20_000 });

    // The payload's own lock control must tear down the shell's session (destroy
    // keys, revoke blob URLs, drop the frame) — the W9 logout path.
    await frame.getByRole("button", { name: "Lock", exact: true }).click();
    await expect(page.locator("#workspace-frame")).toHaveCount(0);
    await expect(page.getByText("Workspace locked.")).toBeVisible();
  });

  test("offers no recovery-passkey control when the server reports none", async ({ page, request }) => {
    const info = await unlockInfo(request);
    test.skip(!info.available, `crypto tooling unavailable: ${info.reason ?? "unknown"}`);

    await unlock(page, info);
    // The test host does not configure the recovery wrapper store, so the shell
    // must not advertise a passkey-recovery path it cannot complete. The offline
    // recovery code remains the only credential.
    await expect(
      page.getByRole("button", { name: "Unlock with a recovery passkey" }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("heading", { name: "Trusted recovery credentials" }),
    ).toHaveCount(0);
  });

  test("descriptor failure offers a retry instead of a dead end", async ({ page }) => {
    await page.route("**/internal/workspace/descriptor", (route) =>
      route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({ code: "unavailable" }),
      }),
    );
    await page.goto(`${SHELL_ORIGIN}/`);
    await expect(page.getByRole("button", { name: "Retry release check" })).toBeVisible();
    await expect(page.locator("#recovery-code")).toHaveCount(0);
  });
});
