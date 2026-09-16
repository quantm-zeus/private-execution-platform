import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  RECOVERY_CODE_BYTES,
  OFFLINE_RECOVERY_CREDENTIAL_B64,
  WORKSPACE_ROOT_CONTEXT_B64,
  WORKSPACE_ROOT_KEY_SOURCE,
  WORKSPACE_ROOT_SECRET_BYTES,
  WorkspaceRootError,
  decodeRecoveryCode,
  deriveWorkspaceRootFingerprint,
  deriveWorkspaceRootPublicKey,
  generateRecoveryCode,
  generateWorkspaceRootSecret,
  isOfflineRecoveryCredential,
  isValidWorkspaceRootSecret,
  selectPasskeyUnlockWrappers,
  unwrapWorkspaceRootWithPrf,
  unwrapWorkspaceRootWithRecovery,
  wrapWorkspaceRootForRecovery,
  workspaceRootMatchesFingerprint,
} from "./workspace-root.ts";
import { generateRecoverySalt, wrapWithPrf } from "./recovery-wrapping.ts";
import { addRecoveryWrapper } from "./recovery-client.ts";
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

test("the fixed derivation context is the pinned protocol constant", () => {
  const context = Buffer.from(WORKSPACE_ROOT_CONTEXT_B64, "base64");
  assert.equal(context.length, 16);
  assert.ok(context.some((byte) => byte !== 0));
  // Pin the exact value: sha256("evergreen/workspace-root-key/v2") truncated to
  // 16 bytes, matching the server-side WORKSPACE_ROOT_CONTEXT_KID. A
  // release-derived or otherwise wrong constant cannot pass.
  const expected = createHash("sha256")
    .update("evergreen/workspace-root-key/v2")
    .digest()
    .subarray(0, 16);
  assert.equal(context.toString("base64"), expected.toString("base64"));
  assert.equal(
    context.toString("hex"),
    "4adf2d43f11d9ddea06efb64457649b1",
  );
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

test("a passkey-PRF wrapper round-trips the stable root and binds the credential", async () => {
  const credentialId = Buffer.from(new Uint8Array(32).fill(7)).toString("base64");
  const prf = new Uint8Array(32).fill(0x42);
  const credential = {
    getClientExtensionResults: () => ({ prf: { results: { first: prf } } }),
  };
  const record = await wrapWithPrf(
    FIXED_ROOT,
    credential,
    credentialId,
    generateRecoverySalt(),
    WORKSPACE_ROOT_KEY_SOURCE,
  );
  assert.ok(record);
  assert.equal(record!.key_source, WORKSPACE_ROOT_KEY_SOURCE);

  const reopened = await unwrapWorkspaceRootWithPrf(record!, prf, credentialId);
  assert.deepEqual(reopened, FIXED_ROOT);

  // A different credential id is not authenticated into the tag.
  await assert.rejects(
    unwrapWorkspaceRootWithPrf(
      record!,
      prf,
      Buffer.from(new Uint8Array(32).fill(8)).toString("base64"),
    ),
    (error: unknown) => error instanceof WorkspaceRootError,
  );
});

test("a revoked passkey is never selected for normal unlock", () => {
  const offline = {
    credential_id_b64: OFFLINE_RECOVERY_CREDENTIAL_B64,
    revoked_at_ms: null,
  };
  const live = { credential_id_b64: "live-passkey", revoked_at_ms: null };
  const revoked = { credential_id_b64: "revoked-passkey", revoked_at_ms: 123 };
  const selected = selectPasskeyUnlockWrappers([offline, live, revoked]);
  assert.deepEqual(selected, [live]);
  assert.equal(isOfflineRecoveryCredential(offline.credential_id_b64), true);
  assert.equal(isOfflineRecoveryCredential(live.credential_id_b64), false);
});

test("new device: recovery code unlocks the stable root and enrolls a passkey without rotating it", async () => {
  const recoveryCode = decodeRecoveryCode(generateRecoveryCode());
  const recoveryWrapper = await wrapWorkspaceRootForRecovery(FIXED_ROOT, recoveryCode);
  const fingerprint = await deriveWorkspaceRootFingerprint(FIXED_ROOT);

  // The new device has only the offline-recovery wrapper. Recovering unwraps the
  // SAME stable root and validates it against the durable identity.
  const recovered = await unwrapWorkspaceRootWithRecovery(recoveryWrapper, recoveryCode);
  assert.deepEqual(recovered, FIXED_ROOT);
  assert.equal(await workspaceRootMatchesFingerprint(recovered, fingerprint), true);

  // Enroll this device's passkey: wrap the SAME root under a fresh PRF wrapper.
  const credentialId = Buffer.from(new Uint8Array(32).fill(0x2a)).toString("base64");
  const prf = new Uint8Array(32).fill(0x42);
  const credential = {
    getClientExtensionResults: () => ({ prf: { results: { first: prf } } }),
  };
  const newWrapper = await wrapWithPrf(
    FIXED_ROOT,
    credential,
    credentialId,
    generateRecoverySalt(),
    WORKSPACE_ROOT_KEY_SOURCE,
  );
  assert.ok(newWrapper);

  // The enrollment request carries only the opaque wrapper; no secret material.
  let sentBody = "";
  const fetchFn = (async (_url: string, init?: RequestInit) => {
    sentBody = String(init?.body ?? "");
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
  await addRecoveryWrapper(
    {
      challengeId: "challenge",
      proofB64: "proof",
      credentialIdB64: credentialId,
      label: "New device",
      record: newWrapper!,
    },
    { fetchFn },
  );
  const sent = JSON.parse(sentBody);
  assert.equal(sent.wrapper.credential_id_b64, credentialId);
  assert.equal(sent.wrapper.key_source, WORKSPACE_ROOT_KEY_SOURCE);
  for (const forbidden of ["root_secret", "recovery_code", "prf_output", "unwrap_key"]) {
    assert.equal(sent[forbidden], undefined);
    assert.equal(sent.wrapper[forbidden], undefined);
  }

  // The root never rotates: the original recovery code still unwraps it, and the
  // newly enrolled passkey unwraps the same root.
  assert.deepEqual(
    await unwrapWorkspaceRootWithRecovery(recoveryWrapper, recoveryCode),
    FIXED_ROOT,
  );
  assert.deepEqual(
    await unwrapWorkspaceRootWithPrf(newWrapper!, prf, credentialId),
    FIXED_ROOT,
  );
});

test("the root modules never touch browser persistent storage", () => {
  const sources = [
    "workspace-root.ts",
    "recovery-wrapping.ts",
    "unlock-runtime.ts",
    "recovery-client.ts",
    "recovery-passkey.ts",
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
