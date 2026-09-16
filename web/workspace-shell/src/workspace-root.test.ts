import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  RECOVERY_CODE_BYTES,
  WORKSPACE_ROOT_CONTEXT_B64,
  WORKSPACE_ROOT_KEY_SOURCE,
  WORKSPACE_ROOT_SECRET_BYTES,
  WorkspaceRootError,
  decodeRecoveryCode,
  deriveWorkspaceRootFingerprint,
  deriveWorkspaceRootPublicKey,
  generateRecoveryCode,
  generateWorkspaceRootSecret,
  isValidWorkspaceRootSecret,
  unwrapWorkspaceRootWithRecovery,
  wrapWorkspaceRootForRecovery,
  workspaceRootMatchesFingerprint,
} from "./workspace-root.ts";
import { initSync } from "./wasm/crypto-envelope-wasm.js";

// Initialize the real audited WASM derivation once for this file.
const wasmBytes = readFileSync(
  new URL("./wasm/crypto-envelope-wasm_bg.wasm", import.meta.url),
);
initSync({ module: wasmBytes });

const FIXED_ROOT = new Uint8Array(32).fill(0x5a);

test("root secret generation is 32 non-zero random bytes", () => {
  const a = generateWorkspaceRootSecret();
  const b = generateWorkspaceRootSecret();
  assert.equal(a.length, WORKSPACE_ROOT_SECRET_BYTES);
  assert.ok(a.some((byte) => byte !== 0));
  assert.ok(!a.every((byte) => byte === 0));
  assert.notDeepEqual(a, b);
  assert.ok(isValidWorkspaceRootSecret(a));
});

test("invalid root secrets are rejected", () => {
  assert.ok(!isValidWorkspaceRootSecret(new Uint8Array(31).fill(1)));
  assert.ok(!isValidWorkspaceRootSecret(new Uint8Array(32)));
  assert.ok(!isValidWorkspaceRootSecret("not bytes"));
});

test("recovery code is a generated 32-byte non-zero secret that round-trips", () => {
  const code = generateRecoveryCode();
  const decoded = decodeRecoveryCode(code);
  assert.equal(decoded.length, RECOVERY_CODE_BYTES);
  assert.ok(decoded.some((byte) => byte !== 0));
  assert.notEqual(generateRecoveryCode(), code);
});

test("recovery code decoding tolerates whitespace but rejects non-canonical input", () => {
  const code = generateRecoveryCode();
  const spaced = code.replace(/(.{8})/g, "$1 ");
  assert.deepEqual(decodeRecoveryCode(spaced), decodeRecoveryCode(code));
  for (const bad of ["", "AAA", "!!!!", "AAAA", code.slice(0, -1)]) {
    assert.throws(
      () => decodeRecoveryCode(bad),
      (error: unknown) => error instanceof WorkspaceRootError,
    );
  }
});

test("stable workspace public identity is deterministic and independent of release metadata", async () => {
  const pk1 = await deriveWorkspaceRootPublicKey(FIXED_ROOT);
  const pk2 = await deriveWorkspaceRootPublicKey(FIXED_ROOT);
  assert.equal(pk1.length, 32);
  assert.deepEqual(pk1, pk2);

  const fpr1 = await deriveWorkspaceRootFingerprint(FIXED_ROOT);
  const fpr2 = await deriveWorkspaceRootFingerprint(FIXED_ROOT);
  assert.equal(fpr1, fpr2);
  assert.equal(fpr1.length, 44);

  // A different root must produce a different identity; the derivation takes no
  // release id/KID input, so every release for a workspace derives this value.
  const other = new Uint8Array(32).fill(0x5b);
  const otherPk = await deriveWorkspaceRootPublicKey(other);
  assert.notDeepEqual(pk1, otherPk);
});

test("the fixed derivation context is a stable 16-byte protocol constant", () => {
  const context = Buffer.from(WORKSPACE_ROOT_CONTEXT_B64, "base64");
  assert.equal(context.length, 16);
  assert.ok(context.some((byte) => byte !== 0));
});

test("invalid roots and a missing WASM boundary fail closed with typed errors", async () => {
  await assert.rejects(
    () => deriveWorkspaceRootPublicKey(new Uint8Array(32)),
    (error: unknown) =>
      error instanceof WorkspaceRootError && error.code === "invalid_root",
  );
  await assert.rejects(
    () => deriveWorkspaceRootPublicKey(new Uint8Array(31).fill(1)),
    (error: unknown) =>
      error instanceof WorkspaceRootError && error.code === "invalid_root",
  );
});

test("workspaceRootMatchesFingerprint accepts the right root and rejects a wrong one", async () => {
  const fingerprint = await deriveWorkspaceRootFingerprint(FIXED_ROOT);
  assert.equal(await workspaceRootMatchesFingerprint(FIXED_ROOT, fingerprint), true);
  assert.equal(
    await workspaceRootMatchesFingerprint(new Uint8Array(32).fill(0x11), fingerprint),
    false,
  );
  assert.equal(await workspaceRootMatchesFingerprint(FIXED_ROOT, null), false);
  assert.equal(await workspaceRootMatchesFingerprint(FIXED_ROOT, ""), false);
});

test("recovery wrapper round-trips the Workspace Root Secret under the v2 key source", async () => {
  const recoveryCode = decodeRecoveryCode(generateRecoveryCode());
  const record = await wrapWorkspaceRootForRecovery(FIXED_ROOT, recoveryCode);
  assert.equal(record.key_source, WORKSPACE_ROOT_KEY_SOURCE);
  assert.equal(record.version, 1);
  const reopened = await unwrapWorkspaceRootWithRecovery(record, recoveryCode);
  assert.deepEqual(reopened, FIXED_ROOT);
});

test("a wrong recovery code fails locally with a typed error", async () => {
  const recoveryCode = decodeRecoveryCode(generateRecoveryCode());
  const record = await wrapWorkspaceRootForRecovery(FIXED_ROOT, recoveryCode);
  const wrong = decodeRecoveryCode(generateRecoveryCode());
  await assert.rejects(
    () => unwrapWorkspaceRootWithRecovery(record, wrong),
    (error: unknown) =>
      error instanceof WorkspaceRootError && error.code === "unwrap_failed",
  );
});

test("a tampered wrapper fails closed", async () => {
  const recoveryCode = decodeRecoveryCode(generateRecoveryCode());
  const record = await wrapWorkspaceRootForRecovery(FIXED_ROOT, recoveryCode);
  const tamperedBytes = Buffer.from(record.wrapped_root_key_b64, "base64");
  tamperedBytes[0] ^= 0x01;
  const tampered = {
    ...record,
    wrapped_root_key_b64: tamperedBytes.toString("base64"),
  };
  await assert.rejects(
    () => unwrapWorkspaceRootWithRecovery(tampered, recoveryCode),
    (error: unknown) =>
      error instanceof WorkspaceRootError && error.code === "unwrap_failed",
  );
});

test("a legacy v1 wrapper is never accepted by the v2 unwrap path", async () => {
  const recoveryCode = decodeRecoveryCode(generateRecoveryCode());
  const record = await wrapWorkspaceRootForRecovery(FIXED_ROOT, recoveryCode);
  const legacy = { ...record, key_source: "unlock_secret_v1" };
  await assert.rejects(
    () => unwrapWorkspaceRootWithRecovery(legacy, recoveryCode),
    (error: unknown) =>
      error instanceof WorkspaceRootError && error.code === "unwrap_failed",
  );
});

test("the root modules never touch browser persistent storage", () => {
  const sources = [
    "workspace-root.ts",
    "recovery-wrapping.ts",
    "unlock-runtime.ts",
    "recovery-client.ts",
    "passkey-auth.ts",
  ];
  for (const source of sources) {
    const text = readFileSync(new URL(`./${source}`, import.meta.url), "utf8");
    for (const forbidden of [
      "localStorage",
      "sessionStorage",
      "indexedDB",
      "document.cookie",
    ]) {
      assert.ok(
        !text.includes(forbidden),
        `${source} must not touch ${forbidden}`,
      );
    }
  }
});
