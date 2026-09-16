import { expect, test } from "@playwright/test";

const SHELL_ORIGIN = `http://127.0.0.1:${process.env.E2E_SHELL_PORT ?? 4320}`;
const ALLOW_SKIP = process.env.E2E_ALLOW_SKIP === "1";

interface UnlockInfo {
  available: boolean;
  reason?: string;
  recoveryCode?: string;
  fingerprintB64?: string;
}

async function unlockInfo(
  request: import("@playwright/test").APIRequestContext,
): Promise<UnlockInfo> {
  const response = await request.get(`${SHELL_ORIGIN}/__test__/unlock`);
  return (await response.json()) as UnlockInfo;
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

/** Reveal the recovery fallback if the shell has not already surfaced it. */
async function openRecovery(page: import("@playwright/test").Page) {
  const recovery = page.locator("#recovery-code");
  const trouble = page.getByRole("button", { name: "Having trouble signing in?" });
  await recovery.or(trouble).first().waitFor({ state: "visible", timeout: 20_000 });
  if (!(await recovery.isVisible())) {
    await trouble.click();
  }
  await expect(recovery).toBeVisible({ timeout: 20_000 });
}

async function unlock(
  page: import("@playwright/test").Page,
  info: UnlockInfo,
) {
  await page.goto(`${SHELL_ORIGIN}/`);
  // The host reports an existing operator session, a configured stable
  // workspace identity, and only an offline recovery wrapper. There is no
  // passkey auto-unlock, so the shell surfaces the recovery action.
  await openRecovery(page);
  await page.locator("#recovery-code").fill(info.recoveryCode!);
  // Snapshot the field at the instant the first unlock network exchange starts.
  // `toHaveValue("")` below retries for up to 7s, so on its own it would also
  // pass if the code were cleared only after the exchange; this route pins the
  // "cleared before the first await" claim.
  let valueAtFirstGrant: string | null = null;
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
  await page.getByRole("button", { name: "Unlock with recovery code" }).click();
  // The code is cleared from the DOM synchronously before the first network
  // await, and the form stays mounted until the payload boots, so this pins the
  // secret-lifetime claim.
  await expect(page.locator("#recovery-code")).toHaveValue("");
  await firstGrantSeen;
  expect(valueAtFirstGrant).toBe("");
  // The payload may announce readiness and overwrite the status text, so wait for
  // the instantiated frame itself rather than a transient status string.
  await expect(page.locator("#workspace-frame")).toBeVisible({ timeout: 20_000 });
}

/**
 * Exercises the real authenticated-unlock boundary: the shell derives the
 * stable workspace key in audited WASM, HPKE-unwraps the encrypted artifact,
 * and instantiates the decrypted payload from `blob:` URLs inside a
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

  test("rejects a wrong recovery code locally without instantiating a payload", async ({ page, request }) => {
    const info = await unlockInfo(request);
    test.skip(!info.available, `crypto tooling unavailable: ${info.reason ?? "unknown"}`);

    await page.goto(`${SHELL_ORIGIN}/`);
    await openRecovery(page);
    await page.locator("#recovery-code").fill(Buffer.alloc(32, 9).toString("base64"));
    await page.getByRole("button", { name: "Unlock with recovery code" }).click();

    // The unwrapped root is checked against the durable identity fingerprint, so
    // a wrong code is rejected locally with actionable guidance.
    await expect(page.locator("#recovery-message")).toContainText(
      /does not match this workspace/i,
      { timeout: 20_000 },
    );
    await expect(page.locator("#workspace-frame")).toHaveCount(0);
    await expect(page.locator("#recovery-code")).toHaveCount(1);
  });

  test("normal login never exposes KID, keys, fingerprints, or a recovery input", async ({ page }) => {
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
    // The recovery form is behind an explicit action, not on the login screen.
    await expect(page.locator("#recovery-code")).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "Having trouble signing in?" }),
    ).toHaveCount(0);
    // No release compatibility, key-binding, reseal or protocol detail leaks.
    const body = (await page.locator("main.gateway").innerText()).toLowerCase();
    for (const forbidden of [
      "kid",
      "public key",
      "fingerprint",
      "reseal",
      "artifact digest",
      "protocol metadata",
      "key binding",
      "enrollment secret",
      "recovery code",
    ]) {
      expect(body, `normal login must not mention ${forbidden}`).not.toContain(forbidden);
    }
    // Bootstrap enrollment stays hidden while the server reports it closed, and
    // can never be reached through the normal login panel.
    await expect(page.getByText("First-run operator enrollment")).toHaveCount(0);
    await expect(page.locator("#enroll-secret")).toHaveCount(0);
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

  test("the recovery input appears only behind the trouble action", async ({ page, request }) => {
    const info = await unlockInfo(request);
    test.skip(!info.available, `crypto tooling unavailable: ${info.reason ?? "unknown"}`);

    await page.goto(`${SHELL_ORIGIN}/`);
    await expect(
      page.getByRole("heading", { name: "Unlock the sealed release" }),
    ).toBeVisible({ timeout: 20_000 });
    // This host has no passkey wrapper, so the shell may have attempted the
    // normal path; the recovery input must still be absent until the explicit
    // "Having trouble signing in?" action is used.
    await expect(page.locator("#recovery-code")).toHaveCount(0);
    await page.getByRole("button", { name: "Having trouble signing in?" }).click();
    await expect(page.locator("#recovery-code")).toBeVisible();
  });

  test("a PRF-unavailable login prompts once and exposes only the recovery fallback", async ({
    page,
    request,
  }) => {
    const info = await unlockInfo(request);
    test.skip(!info.available, `crypto tooling unavailable: ${info.reason ?? "unknown"}`);
    // Drive the real shell orchestration with TWO active passkey wrappers and a
    // synthetic authenticator that authenticates but returns NO PRF output. The
    // two wrappers exist so a per-wrapper ceremony loop would show up as more
    // than one `credentials.get()` call; the single ceremony must not repeat,
    // and the normal surface must fail closed to the explicit recovery action.
    const passkeyWrapper = (credentialId: Buffer) => ({
      credential_id_b64: credentialId.toString("base64"),
      label: "This device",
      version: 1,
      algorithm: "HKDF-SHA256/AES-256-GCM",
      key_source: "workspace_root_v2",
      salt_b64: Buffer.alloc(32, 1).toString("base64"),
      iv_b64: Buffer.alloc(12, 2).toString("base64"),
      wrapped_root_key_b64: Buffer.alloc(48, 3).toString("base64"),
      created_at_ms: 1,
      last_used_at_ms: null,
      revoked_at_ms: null,
    });
    await page.route("**/internal/workspace/recovery", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          wrappers: [
            passkeyWrapper(Buffer.from([1, 2, 3])),
            passkeyWrapper(Buffer.from([4, 5, 6])),
          ],
        }),
      }),
    );
    await page.route("**/internal/auth/challenge", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          publicKey: {
            challenge: "AQID",
            rpId: "127.0.0.1",
            allowCredentials: [{ id: "AQID", type: "public-key" }],
          },
        }),
      }),
    );
    await page.route("**/internal/auth/verify", (route) =>
      route.fulfill({ status: 204, body: "" }),
    );
    await page.addInitScript(() => {
      (window as unknown as { __passkeyGetCalls: number }).__passkeyGetCalls = 0;
      const container = navigator.credentials as unknown as Record<string, unknown>;
      container.get = async () => {
        (window as unknown as { __passkeyGetCalls: number }).__passkeyGetCalls += 1;
        return {
          id: "cred",
          rawId: new Uint8Array([1, 2, 3]).buffer,
          type: "public-key",
          response: {
            clientDataJSON: new Uint8Array([1]).buffer,
            authenticatorData: new Uint8Array([2]).buffer,
            signature: new Uint8Array([3]).buffer,
            userHandle: null,
          },
          getClientExtensionResults: () => ({ prf: {} }),
        };
      };
    });

    await page.goto(`${SHELL_ORIGIN}/`);
    const unlockButton = page.getByRole("button", { name: "Unlock with passkey" });
    await expect(unlockButton).toBeVisible({ timeout: 20_000 });
    await unlockButton.click();

    // The single ceremony authenticates once, then fails closed to recovery:
    // the recovery form stays behind the explicit action, the passkey retry is
    // withdrawn, and no second prompt is launched.
    await expect(
      page.getByRole("button", { name: "Having trouble signing in?" }),
    ).toBeVisible({ timeout: 20_000 });
    await expect(page.locator("#recovery-code")).toHaveCount(0);
    await expect(unlockButton).toHaveCount(0);
    // Prove the unlock path itself ran (and failed closed) before counting, so
    // the counter below cannot pass before `runAutoUnlock` executes — and a
    // per-wrapper ceremony loop would still be visible in the count.
    await expect(page.locator("#status")).toContainText(
      "Automatic passkey unlock was not available",
      { timeout: 20_000 },
    );
    expect(
      await page.evaluate(
        () => (window as unknown as { __passkeyGetCalls: number }).__passkeyGetCalls,
      ),
    ).toBe(1);
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
    // The operator bootstrap is a separate surface, never part of the normal
    // login panel, and behind an explicit operator action.
    await expect(
      page.getByRole("heading", { name: "First-run operator enrollment" }),
    ).toBeVisible();
    await expect(
      page.locator('section[aria-labelledby="open-heading"] #enroll-secret'),
    ).toHaveCount(0);
    await expect(page.locator("#enroll-secret")).toHaveCount(0);
    await page.getByRole("button", { name: "Open operator enrollment" }).click();
    await expect(page.locator("#enroll-secret")).toBeVisible();
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
    // Authenticated + identity loaded: the recovery fallback is mounted, which
    // the signed-out scan does not cover.
    await openRecovery(page);
    await page.addScriptTag({ url: "/__test__/axe.min.js" });
    expect(await axeViolations(), "authenticated unlock surface").toEqual([]);

    // Trigger the credential-failure alert and scan that security-relevant state.
    await page.locator("#recovery-code").fill(Buffer.alloc(32, 9).toString("base64"));
    await page.getByRole("button", { name: "Unlock with recovery code" }).click();
    await expect(page.locator("#recovery-message")).toBeVisible({ timeout: 20_000 });
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

    await openRecovery(page);
    const primary = page.getByRole("button", { name: "Unlock with recovery code" });
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
