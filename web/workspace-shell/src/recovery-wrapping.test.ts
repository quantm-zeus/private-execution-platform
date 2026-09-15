import assert from "node:assert/strict";
import { test } from "node:test";

import {
  RECOVERY_WRAPPER_VERSION,
  RECOVERY_WRAP_ALGORITHM,
  RecoveryWrappingError,
  extractPrfOutput,
  generateRecoverySalt,
  generateWorkspaceRootKey,
  unwrapRootKey,
  unwrapWithPrf,
  unwrapWithRecoverySecret,
  wrapRootKey,
  wrapWithPrf,
  wrapWithRecoverySecret,
} from "./recovery-wrapping.ts";

const SECRET = new Uint8Array(32).fill(0x5a);

function prfCredential(bytes: Uint8Array | null): unknown {
  return {
    getClientExtensionResults: () =>
      bytes
        ? { prf: { enabled: true, results: { first: bytes } } }
        : { prf: {} },
  };
}

test("root keys and salts are random 32-byte values", () => {
  const a = generateWorkspaceRootKey();
  const b = generateWorkspaceRootKey();
  assert.equal(a.length, 32);
  assert.equal(b.length, 32);
  assert.notDeepEqual(a, b);
  assert.ok(a.some((byte) => byte !== 0));
  assert.equal(generateRecoverySalt().length, 32);
});

test("offline recovery secret wraps and unwraps a root key", async () => {
  const rootKey = generateWorkspaceRootKey();
  const record = await wrapWithRecoverySecret(rootKey, SECRET);
  assert.equal(record.version, RECOVERY_WRAPPER_VERSION);
  assert.equal(record.algorithm, RECOVERY_WRAP_ALGORITHM);
  assert.ok(!record.wrapped_root_key_b64.includes("\n"));
  const unwrapped = await unwrapWithRecoverySecret(record, SECRET);
  assert.deepEqual(unwrapped, rootKey);
});

test("a wrong recovery secret or a tampered record fails closed", async () => {
  const rootKey = generateWorkspaceRootKey();
  const record = await wrapWithRecoverySecret(rootKey, SECRET);
  const wrong = new Uint8Array(32).fill(0x5b);
  await assert.rejects(
    unwrapWithRecoverySecret(record, wrong),
    (error: unknown) =>
      error instanceof RecoveryWrappingError && error.code === "unwrap_failed",
  );

  const tampered = {
    ...record,
    wrapped_root_key_b64: `${record.wrapped_root_key_b64.slice(0, -4)}AAAA`,
  };
  await assert.rejects(unwrapWithRecoverySecret(tampered, SECRET));

  await assert.rejects(
    unwrapRootKey(SECRET, { ...record, version: 99 }),
    (error: unknown) =>
      error instanceof RecoveryWrappingError && error.code === "invalid_record",
  );
  await assert.rejects(
    unwrapRootKey(SECRET, { ...record, algorithm: "plain" }),
    (error: unknown) =>
      error instanceof RecoveryWrappingError && error.code === "invalid_record",
  );
});

test("a different salt derives a different wrapping key", async () => {
  const rootKey = generateWorkspaceRootKey();
  const record = await wrapRootKey(SECRET, rootKey);
  const otherSalt = generateRecoverySalt();
  await assert.rejects(unwrapRootKey(SECRET, { ...record, salt_b64: b64(otherSalt) }));
});

test("invalid root keys are refused before any wrapping", async () => {
  await assert.rejects(
    wrapWithRecoverySecret(new Uint8Array(31), SECRET),
    (error: unknown) =>
      error instanceof RecoveryWrappingError && error.code === "invalid_root_key",
  );
  await assert.rejects(
    wrapWithRecoverySecret(new Uint8Array(32), SECRET),
    (error: unknown) =>
      error instanceof RecoveryWrappingError && error.code === "invalid_root_key",
  );
});

test("PRF output is extracted only when the authenticator produced one", () => {
  const bytes = new Uint8Array(32).fill(9);
  assert.deepEqual(extractPrfOutput(prfCredential(bytes)), bytes);
  assert.equal(extractPrfOutput(prfCredential(null)), null);
  assert.equal(extractPrfOutput(null), null);
  assert.equal(extractPrfOutput({}), null);
  assert.equal(
    extractPrfOutput({
      getClientExtensionResults: () => {
        throw new Error("boom");
      },
    }),
    null,
  );
});

test("passkey wrapping requires a verified PRF output", async () => {
  const rootKey = generateWorkspaceRootKey();
  assert.equal(await wrapWithPrf(rootKey, prfCredential(null)), null);
  assert.equal(await unwrapWithPrf({} as never, prfCredential(null)), null);

  const prf = new Uint8Array(32).fill(0x33);
  const record = await wrapWithPrf(rootKey, prfCredential(prf));
  assert.ok(record);
  const unwrapped = await unwrapWithPrf(record!, prfCredential(prf));
  assert.deepEqual(unwrapped, rootKey);

  // A different PRF output (another authenticator) cannot unwrap.
  await assert.rejects(unwrapWithPrf(record!, prfCredential(new Uint8Array(32).fill(0x34))));
});

function b64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
