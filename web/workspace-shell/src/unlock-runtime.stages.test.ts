import assert from "node:assert/strict";
import { test } from "node:test";

import { WorkspaceUnlockRuntime } from "./unlock-runtime.ts";
import { isUnlockError, type UnlockReason, type UnlockStage } from "./unlock-stages.ts";
import type { WorkspaceDescriptor } from "./descriptor.ts";

function descriptor(overrides: Partial<WorkspaceDescriptor> = {}): WorkspaceDescriptor {
  return {
    protocol_version: 1,
    artifact_version: 1,
    artifact_kid_b64: "AAAAAAAAAAAAAAAAAAAAAA==",
    artifact_size: 0,
    artifact_sha256_hex: "",
    package_format_version: 1,
    release_id: null,
    source_sha: null,
    expected_public_key_fingerprint_b64: null,
    min_shell_protocol: 1,
    max_shell_protocol: 1,
    enrolled: false,
    enrolled_kid_b64: null,
    enrolled_public_key_fingerprint_b64: null,
    ...overrides,
  };
}

async function expectStage(
  run: () => Promise<unknown>,
  stage: UnlockStage,
  reason: UnlockReason,
): Promise<void> {
  try {
    await run();
    assert.fail(`expected unlock to fail with ${stage}/${reason}`);
  } catch (error) {
    assert.ok(isUnlockError(error), `expected UnlockError, got ${String(error)}`);
    assert.equal(error.stage, stage);
    assert.equal(error.reason, reason);
  }
}

test("all-zero and short recovery codes fail as U2 before any network", async () => {
  const runtime = new WorkspaceUnlockRuntime();
  await expectStage(
    () => runtime.unlock(new Uint8Array(32), descriptor()),
    "U2_ENROLL",
    "invalid_secret",
  );
  await expectStage(
    () => runtime.unlock(new Uint8Array(31).fill(7), descriptor()),
    "U2_ENROLL",
    "invalid_secret",
  );
});

test("the caller's secret buffer is never zeroized by the runtime", async () => {
  const runtime = new WorkspaceUnlockRuntime();
  const secret = new Uint8Array(32).fill(9);
  await expectStage(
    () => runtime.unlock(secret, descriptor({ artifact_version: 2 })),
    "U5_ARTIFACT",
    "protocol_incompatible",
  );
  assert.equal(secret[0], 9);
  assert.equal(secret[31], 9);
});

test("an incompatible shell protocol fails as U5", async () => {
  const runtime = new WorkspaceUnlockRuntime();
  const secret = new Uint8Array(32).fill(1);
  await expectStage(
    () =>
      runtime.unlock(
        secret,
        descriptor({ min_shell_protocol: 2, max_shell_protocol: 3 }),
      ),
    "U5_ARTIFACT",
    "protocol_incompatible",
  );
  await expectStage(
    () => runtime.unlock(secret, descriptor({ package_format_version: 2 })),
    "U5_ARTIFACT",
    "protocol_incompatible",
  );
});

test("a malformed or all-zero descriptor KID fails as U5", async () => {
  const runtime = new WorkspaceUnlockRuntime();
  const secret = new Uint8Array(32).fill(1);
  await expectStage(
    () => runtime.unlock(secret, descriptor({ artifact_kid_b64: "!!!" })),
    "U5_ARTIFACT",
    "descriptor_invalid",
  );
  await expectStage(
    () =>
      runtime.unlock(
        secret,
        descriptor({ artifact_kid_b64: "AAAAAAAAAAAAAAAAAAAAAA==" }),
      ),
    "U5_ARTIFACT",
    "descriptor_invalid",
  );
});

test("a WASM loader failure is classified as U1", async () => {
  const runtime = new WorkspaceUnlockRuntime();
  const secret = new Uint8Array(32).fill(1);
  await expectStage(
    () =>
      runtime.unlock(secret, descriptor({ artifact_kid_b64: "AQIDBAUGBwgJCgsMDQ4PEA==" }), {
        wasmLoader: async () => {
          throw new Error("wasm unavailable /secret-path");
        },
      }),
    "U1_WASM",
    "wasm_unavailable",
  );
  // The classification must not carry the loader's message.
  try {
    await runtime.unlock(secret, descriptor({ artifact_kid_b64: "AQIDBAUGBwgJCgsMDQ4PEA==" }), {
      wasmLoader: async () => {
        throw new Error("wasm unavailable /secret-path");
      },
    });
    assert.fail("expected the second unlock to fail");
  } catch (error) {
    assert.ok(isUnlockError(error));
    assert.ok(!error.message.includes("secret-path"));
  }
});
