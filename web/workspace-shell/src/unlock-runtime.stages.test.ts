import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { WorkspaceUnlockRuntime, loadWasm, toBase64 } from "./unlock-runtime.ts";
import { isUnlockError, type UnlockReason, type UnlockStage } from "./unlock-stages.ts";
import type { WorkspaceDescriptor } from "./descriptor.ts";

// A real KID (16 non-zero bytes) so the runtime reaches the network boundary.
const VALID_KID_B64 = "AQIDBAUGBwgJCgsMDQ4PEA==";
const WASM_BYTES = readFileSync(
  fileURLToPath(new URL("./wasm/crypto-envelope-wasm_bg.wasm", import.meta.url)),
);

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

function netDescriptor(): WorkspaceDescriptor {
  return descriptor({ artifact_kid_b64: VALID_KID_B64 });
}

function grantResponse(): Response {
  return new Response(
    JSON.stringify({
      grant_id: "grant",
      kid: toBase64(new Uint8Array(16).fill(3)),
      recipient_public_key: toBase64(new Uint8Array(32).fill(9)),
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

test("every unlock POST is same-origin and uses redirect:error", async () => {
  await loadWasm({ module_or_path: WASM_BYTES });
  const runtime = new WorkspaceUnlockRuntime();
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchFn = (async (url: string, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const target = String(url);
    if (target.includes("/artifact/grant")) return grantResponse();
    if (target === "/internal/artifact") {
      return new Response(new Uint8Array(64), { status: 200 });
    }
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;

  await expectStage(
    () => runtime.unlock(new Uint8Array(32).fill(7), netDescriptor(), { fetchFn }),
    "U4_TRANSPORT",
    "transport_rejected",
  );

  assert.deepEqual(
    calls.map((call) => call.url),
    ["/internal/auth/enroll", "/internal/artifact/grant", "/internal/artifact"],
  );
  for (const call of calls) {
    assert.equal(call.init.redirect, "error", `${call.url} must use redirect:error`);
    assert.equal(call.init.credentials, "same-origin");
    assert.equal(call.init.method, "POST");
  }
  // A failed transport decrypt must not leave key material or blob URLs around.
  assert.equal(runtime.unlocked, false);
  assert.equal(runtime.getActiveUrlCount(), 0);
});

test("an expired session on grant maps to U2/session_expired", async () => {
  await loadWasm({ module_or_path: WASM_BYTES });
  const runtime = new WorkspaceUnlockRuntime();
  const fetchFn = (async (url: string) => {
    if (String(url).includes("/artifact/grant")) {
      return new Response(null, { status: 401 });
    }
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;

  await expectStage(
    () => runtime.unlock(new Uint8Array(32).fill(7), netDescriptor(), { fetchFn }),
    "U2_ENROLL",
    "session_expired",
  );
});

test("an expired session on deliver maps to U2/session_expired", async () => {
  await loadWasm({ module_or_path: WASM_BYTES });
  const runtime = new WorkspaceUnlockRuntime();
  const fetchFn = (async (url: string) => {
    const target = String(url);
    if (target.includes("/artifact/grant")) return grantResponse();
    if (target === "/internal/artifact") {
      return new Response(null, { status: 401 });
    }
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;

  await expectStage(
    () => runtime.unlock(new Uint8Array(32).fill(7), netDescriptor(), { fetchFn }),
    "U2_ENROLL",
    "session_expired",
  );
});

test("a 403 on grant or deliver stays a generic rejection, not session expiry", async () => {
  await loadWasm({ module_or_path: WASM_BYTES });
  const grantRuntime = new WorkspaceUnlockRuntime();
  const grantFetch = (async (url: string) => {
    if (String(url).includes("/artifact/grant")) {
      return new Response(null, { status: 403 });
    }
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
  await expectStage(
    () => grantRuntime.unlock(new Uint8Array(32).fill(7), netDescriptor(), { fetchFn: grantFetch }),
    "U3_GRANT",
    "grant_rejected",
  );

  const deliverRuntime = new WorkspaceUnlockRuntime();
  const deliverFetch = (async (url: string) => {
    const target = String(url);
    if (target.includes("/artifact/grant")) return grantResponse();
    if (target === "/internal/artifact") {
      return new Response(null, { status: 403 });
    }
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
  await expectStage(
    () => deliverRuntime.unlock(new Uint8Array(32).fill(7), netDescriptor(), { fetchFn: deliverFetch }),
    "U4_TRANSPORT",
    "transport_rejected",
  );
});
