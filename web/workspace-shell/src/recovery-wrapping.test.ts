import assert from "node:assert/strict";
import { test } from "node:test";

import {
  RECOVERY_AAD,
  RECOVERY_KEY_SOURCE,
  RECOVERY_WRAPPER_VERSION,
  RECOVERY_WRAP_ALGORITHM,
  RecoveryWrappingError,
  deriveRecoveryWrappingKey,
  extractPrfOutput,
  generateRecoverySalt,
  generateWorkspaceRootKey,
  recoveryAadContext,
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
  // 32-byte root key + 16-byte AES-GCM tag.
  assert.equal(atob(record.wrapped_root_key_b64).length, 48);
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

test("passkey wrapping requires a verified PRF output and binds the credential id", async () => {
  const rootKey = generateWorkspaceRootKey();
  const credentialId = b64(new Uint8Array(32).fill(0x44));
  assert.equal(
    await wrapWithPrf(rootKey, prfCredential(null), credentialId),
    null,
  );
  assert.equal(
    await unwrapWithPrf({} as never, prfCredential(null), credentialId),
    null,
  );

  const prf = new Uint8Array(32).fill(0x33);
  const record = await wrapWithPrf(rootKey, prfCredential(prf), credentialId);
  assert.ok(record);
  const unwrapped = await unwrapWithPrf(
    record!,
    prfCredential(prf),
    credentialId,
  );
  assert.deepEqual(unwrapped, rootKey);

  // A different PRF output (another authenticator) cannot unwrap.
  await assert.rejects(
    unwrapWithPrf(record!, prfCredential(new Uint8Array(32).fill(0x34)), credentialId),
  );
  // Nor can the same PRF output reassigned to another credential id: the id is
  // bound into the AEAD tag, so these helpers interoperate only with the
  // production credential-bound records.
  await assert.rejects(
    unwrapWithPrf(record!, prfCredential(prf), b64(new Uint8Array(32).fill(0x45))),
  );
});

test("a bare-AAD legacy record still unwraps while bound records stay bound", async () => {
  // Intermediate branch builds wrote wrappers with the bare domain-constant AAD
  // (no credential id), so the compatibility fallback keeps those readable. It
  // cannot downgrade a bound record: the two AADs are distinct, so a tag made
  // under the bound AAD fails under the bare one.
  const rootKey = generateWorkspaceRootKey();
  const prf = new Uint8Array(32).fill(0x21);
  const salt = generateRecoverySalt();
  const iv = new Uint8Array(12).fill(5);
  const wrappingKey = await deriveRecoveryWrappingKey(prf, salt);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as unknown as BufferSource,
      additionalData: new TextEncoder().encode(RECOVERY_AAD) as unknown as BufferSource,
    },
    wrappingKey,
    rootKey as unknown as BufferSource,
  );
  const legacyRecord = {
    version: RECOVERY_WRAPPER_VERSION,
    algorithm: RECOVERY_WRAP_ALGORITHM,
    key_source: RECOVERY_KEY_SOURCE,
    salt_b64: b64(salt),
    iv_b64: b64(iv),
    wrapped_root_key_b64: b64(new Uint8Array(ciphertext)),
  };
  // (b) A legacy bare-AAD record still unwraps.
  assert.deepEqual(await unwrapRootKey(prf, legacyRecord), rootKey);

  // (a) The production credential-bound AAD round-trips.
  const credentialId = b64(new Uint8Array(32).fill(0x46));
  const bound = await wrapRootKey(prf, rootKey, salt, undefined, credentialId);
  assert.deepEqual(
    await unwrapRootKey(prf, bound, undefined, credentialId),
    rootKey,
  );

  // (c) A bound record must not unwrap under a different credential id.
  await assert.rejects(
    unwrapRootKey(prf, bound, undefined, b64(new Uint8Array(32).fill(0x48))),
    (error: unknown) =>
      error instanceof RecoveryWrappingError && error.code === "unwrap_failed",
  );
});

test("a successful decrypt with a degenerate plaintext surfaces invalid_root_key", async () => {
  // GCM authenticates, but the plaintext is not a valid 32-byte non-zero root
  // key. That must be reported as invalid_root_key, not masked as unwrap_failed.
  const ikm = new Uint8Array(32).fill(0x51);
  const salt = generateRecoverySalt();
  const iv = new Uint8Array(12).fill(6);
  const credentialId = b64(new Uint8Array(32).fill(0x47));
  const record = {
    version: RECOVERY_WRAPPER_VERSION,
    algorithm: RECOVERY_WRAP_ALGORITHM,
    key_source: RECOVERY_KEY_SOURCE,
  };
  const wrappingKey = await deriveRecoveryWrappingKey(ikm, salt);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as unknown as BufferSource,
      additionalData: recoveryAadContext(
        record,
        credentialId,
      ) as unknown as BufferSource,
    },
    wrappingKey,
    new Uint8Array(32) as unknown as BufferSource,
  );
  await assert.rejects(
    unwrapRootKey(
      ikm,
      {
        ...record,
        salt_b64: b64(salt),
        iv_b64: b64(iv),
        wrapped_root_key_b64: b64(new Uint8Array(ciphertext)),
      },
      undefined,
      credentialId,
    ),
    (error: unknown) =>
      error instanceof RecoveryWrappingError && error.code === "invalid_root_key",
  );
});

test("random generation fails closed when WebCrypto is unavailable", () => {
  const original = globalThis.crypto;
  try {
    Object.defineProperty(globalThis, "crypto", {
      value: undefined,
      configurable: true,
    });
    assert.throws(
      () => generateWorkspaceRootKey(),
      (error: unknown) =>
        error instanceof RecoveryWrappingError &&
        error.code === "crypto_unavailable",
    );
    assert.throws(
      () => generateRecoverySalt(),
      (error: unknown) =>
        error instanceof RecoveryWrappingError &&
        error.code === "crypto_unavailable",
    );
  } finally {
    Object.defineProperty(globalThis, "crypto", {
      value: original,
      configurable: true,
    });
  }
});

function b64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
