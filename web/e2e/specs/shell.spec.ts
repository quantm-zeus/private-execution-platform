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
  await page.locator("#unlock-secret").fill(info.secretB64!);
  await page.locator("#unlock-kid").fill(info.kidB64!);
  await page.getByRole("button", { name: "Unlock Workspace" }).click();
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
    await page.locator("#unlock-secret").fill(Buffer.alloc(32, 9).toString("base64"));
    await page.locator("#unlock-kid").fill(info.kidB64!);
    await page.getByRole("button", { name: "Unlock Workspace" }).click();

    await expect(page.getByText(/unlock failed|workspace unavailable/i)).toBeVisible({
      timeout: 20_000,
    });
    await expect(page.locator("#workspace-frame")).toHaveCount(0);
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
});
