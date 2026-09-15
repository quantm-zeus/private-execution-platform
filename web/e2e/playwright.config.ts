import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.E2E_PORT ?? 4319);
const SHELL_PORT = Number(process.env.E2E_SHELL_PORT ?? 4320);

export default defineConfig({
  testDir: "./specs",
  timeout: 30_000,
  expect: { timeout: 7_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "retain-on-failure",
    video: "off",
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      command: "node server.mjs",
      url: `http://127.0.0.1:${PORT}/__test__/state`,
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      // Real shell unlock host (HPKE + artifact sealing) for the shell spec.
      command: "node shell-server.mjs",
      url: `http://127.0.0.1:${SHELL_PORT}/__test__/unlock`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
  // Chromium is the reference engine (the audited HPKE/WASM unlock path and the
  // WebAuthn ceremony harness). Firefox is a second, independent engine for the
  // non-WebAuthn portions: the shell mocks `navigator.credentials` and reports an
  // existing operator session, so the production-faithful unlock host and every
  // payload surface run against a different layout/runtime engine.
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
  ],
});
