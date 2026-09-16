// Focused tests for the single-ceremony Workspace Root Key unlock.
//
// These pin the GPT-5.6 Sol/high Root-Key V2 remediation contract:
//   * the normal login is exactly ONE navigator.credentials.get();
//   * the asserted credential id selects exactly one wrapper (no per-wrapper
//     ceremony loop), even with many active wrappers;
//   * a PRF-unavailable login returns null and triggers no second prompt;
//   * a synced/new-device passkey with a usable PRF unwraps in that ceremony;
//   * signature bytes are never key material and PRF output is zeroized on
//     every success and failure path.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { authenticateWithPasskey } from "./passkey-auth.ts";
import {
  RECOVERY_WRAP_ALGORITHM,
  RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2,
  generateRecoverySalt,
  wrapRootKey,
  wrapWithPrf,
} from "./recovery-wrapping.ts";
import type { RecoveryWrapperRecord } from "./recovery-client.ts";
import {
  WORKSPACE_ROOT_KEY_SOURCE,
  deriveWorkspaceRootFingerprint,
} from "./workspace-root.ts";
import {
  WorkspaceUnlockError,
  unwrapRootFromAssertion,
} from "./workspace-unlock.ts";
import { initSync } from "./wasm/crypto-envelope-wasm.js";

// Initialize the real audited WASM derivation once for the round-trip test.
const wasmBytes = readFileSync(
  new URL("./wasm/crypto-envelope-wasm_bg.wasm", import.meta.url),
);
initSync({ module: wasmBytes });

const buffer = (...values: number[]): ArrayBuffer =>
  new Uint8Array(values).buffer as ArrayBuffer;

function challengeResponse(): Response {
  return new Response(
    JSON.stringify({
      publicKey: {
        challenge: "AQID",
        rpId: "example.com",
        allowCredentials: [{ id: "AQID", type: "public-key" }],
      },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

function verifyFetch(): typeof fetch {
  return (async (url: string) => {
    if (String(url).includes("challenge")) return challengeResponse();
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
}

/** A synthetic wrapper record; its crypto fields are opaque to injected deps. */
function wrapperRecord(
  credentialIdB64: string,
  overrides: Partial<RecoveryWrapperRecord> = {},
): RecoveryWrapperRecord {
  return {
    credential_id_b64: credentialIdB64,
    label: "device",
    version: 1,
    algorithm: RECOVERY_WRAP_ALGORITHM,
    key_source: RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2,
    salt_b64: "AAAA",
    iv_b64: "AAAA",
    wrapped_root_key_b64: "AAAA",
    created_at_ms: 1,
    last_used_at_ms: null,
    revoked_at_ms: null,
    ...overrides,
  };
}

function prfCredential(prfBytes: Uint8Array, rawId: ArrayBuffer): PublicKeyCredential {
  return {
    id: "cred",
    rawId,
    type: "public-key",
    response: {
      clientDataJSON: buffer(4, 5),
      authenticatorData: buffer(6),
      signature: buffer(0xde, 0xad),
      userHandle: null,
    },
    getClientExtensionResults: () =>
      ({ prf: { results: { first: prfBytes } } }),
  } as unknown as PublicKeyCredential;
}

test("multiple active wrappers still use one ceremony and select the asserted credential", async () => {
  const prf = new Uint8Array(32).fill(0x11);
  let getCalls = 0;
  const credentials = {
    get: async () => {
      getCalls += 1;
      // The user selected credential A; the server advertised A, B and C.
      return prfCredential(prf, buffer(1, 2, 3));
    },
  } as unknown as CredentialsContainer;

  const assertion = await authenticateWithPasskey({
    credentials,
    fetchFn: verifyFetch(),
  });
  assert.equal(getCalls, 1, "exactly one ceremony regardless of wrapper count");

  const wrappers = [
    wrapperRecord("BAUG"), // B
    wrapperRecord("AQID"), // A (the asserted credential)
    wrapperRecord("BwgJ"), // C
  ];
  const unwrappedWith: string[] = [];
  const root = await unwrapRootFromAssertion(
    assertion,
    wrappers,
    "fingerprint",
    {
      unwrapWithPrfOutput: async (prfOutput, record) => {
        unwrappedWith.push(record.credential_id_b64 ?? "");
        assert.deepEqual(prfOutput, prf);
        return new Uint8Array(32).fill(0x99);
      },
      matchesFingerprint: async () => true,
    },
  );
  assert.equal(getCalls, 1, "unlock must not launch another ceremony");
  assert.equal(unwrappedWith.length, 1);
  assert.equal(unwrappedWith[0], "AQID");
  assert.deepEqual(root, new Uint8Array(32).fill(0x99));
  assert.ok(
    assertion.prfOutput!.every((byte) => byte === 0),
    "PRF zeroized after a successful unwrap",
  );
});

test("a null PRF output fails closed without unwrapping or prompting again", async () => {
  let getCalls = 0;
  const credentials = {
    get: async () => {
      getCalls += 1;
      return {
        id: "cred",
        rawId: buffer(1, 2, 3),
        type: "public-key",
        response: {
          clientDataJSON: buffer(4, 5),
          authenticatorData: buffer(6),
          signature: buffer(7, 8),
          userHandle: null,
        },
        getClientExtensionResults: () => ({ prf: {} }),
      } as unknown as PublicKeyCredential;
    },
  } as unknown as CredentialsContainer;

  const assertion = await authenticateWithPasskey({
    credentials,
    fetchFn: verifyFetch(),
  });
  assert.equal(assertion.prfOutput, null);

  let unwrapCalls = 0;
  await assert.rejects(
    unwrapRootFromAssertion(assertion, [wrapperRecord("AQID")], "fingerprint", {
      unwrapWithPrfOutput: async () => {
        unwrapCalls += 1;
        return new Uint8Array(32);
      },
      matchesFingerprint: async () => true,
    }),
    (error: unknown) =>
      error instanceof WorkspaceUnlockError && error.code === "prf_unavailable",
  );
  assert.equal(unwrapCalls, 0, "an absent PRF must not reach the unwrap");
  assert.equal(getCalls, 1, "an absent PRF must not trigger a second prompt");
});

test("an asserted credential with no live wrapper fails closed", async () => {
  const prf = new Uint8Array(32).fill(0x22);
  const assertion = {
    credentialIdB64: "AQID",
    prfOutput: prf.slice(),
  };
  const wrappers = [
    wrapperRecord("BAUG"),
    // The offline recovery record is never a normal-unlock candidate.
    wrapperRecord("b2ZmbGluZQ=="),
    wrapperRecord("AQID", { revoked_at_ms: 123 }), // revoked passkey
  ];
  let unwrapCalls = 0;
  await assert.rejects(
    unwrapRootFromAssertion(assertion, wrappers, "fingerprint", {
      unwrapWithPrfOutput: async () => {
        unwrapCalls += 1;
        return new Uint8Array(32);
      },
      matchesFingerprint: async () => true,
    }),
    (error: unknown) =>
      error instanceof WorkspaceUnlockError &&
      error.code === "no_matching_wrapper",
  );
  assert.equal(unwrapCalls, 0);
});

test("a failed unwrap or a mismatched fingerprint fails closed and zeroizes the PRF", async () => {
  const prf = new Uint8Array(32).fill(0x44);
  const assertion = { credentialIdB64: "AQID", prfOutput: prf.slice() };

  await assert.rejects(
    unwrapRootFromAssertion(assertion, [wrapperRecord("AQID")], "fingerprint", {
      unwrapWithPrfOutput: async () => {
        throw new Error("tampered wrapper");
      },
      matchesFingerprint: async () => true,
    }),
    (error: unknown) =>
      error instanceof WorkspaceUnlockError && error.code === "unwrap_failed",
  );
  assert.ok(assertion.prfOutput.every((byte) => byte === 0), "PRF zeroized after failure");

  const wrongRoot = new Uint8Array(32).fill(0x55);
  const mismatchAssertion = { credentialIdB64: "AQID", prfOutput: new Uint8Array(32).fill(0x66) };
  await assert.rejects(
    unwrapRootFromAssertion(
      mismatchAssertion,
      [wrapperRecord("AQID")],
      "expected-fingerprint",
      {
        unwrapWithPrfOutput: async () => wrongRoot,
        matchesFingerprint: async () => false,
      },
    ),
    (error: unknown) =>
      error instanceof WorkspaceUnlockError &&
      error.code === "fingerprint_mismatch",
  );
  assert.ok(wrongRoot.every((byte) => byte === 0), "wrong root zeroized on mismatch");
  assert.ok(
    mismatchAssertion.prfOutput.every((byte) => byte === 0),
    "PRF zeroized after mismatch",
  );
});

test("a synced/new-device passkey unwraps the same stable root in one ceremony", async () => {
  const root = new Uint8Array(32).fill(0x42);
  const fingerprint = await deriveWorkspaceRootFingerprint(root);
  const prf = new Uint8Array(32).fill(0x24);
  const credentialIdB64 = "AQID";
  const credential = prfCredential(prf, buffer(1, 2, 3));

  // Wrapper created once (on the original device) under the stable root.
  const wrapped = await wrapWithPrf(
    root,
    credential,
    credentialIdB64,
    generateRecoverySalt(),
    WORKSPACE_ROOT_KEY_SOURCE,
  );
  assert.ok(wrapped);
  const record: RecoveryWrapperRecord = {
    ...wrapped!,
    credential_id_b64: credentialIdB64,
    label: "Synced passkey",
    created_at_ms: 1,
    last_used_at_ms: null,
    revoked_at_ms: null,
  };

  // The same synced credential on a NEW device: identical credential id and
  // PRF, different signature bytes. It must unlock in one ceremony.
  let getCalls = 0;
  const newDevice = {
    get: async () => {
      getCalls += 1;
      const base = prfCredential(prf, buffer(1, 2, 3));
      (base.response as unknown as { signature: ArrayBuffer }).signature = buffer(0x99, 0x98);
      return base;
    },
  } as unknown as CredentialsContainer;

  const assertion = await authenticateWithPasskey({
    credentials: newDevice,
    fetchFn: verifyFetch(),
  });
  assert.equal(getCalls, 1);
  const unwrapped = await unwrapRootFromAssertion(assertion, [record], fingerprint);
  assert.deepEqual(unwrapped, root);
  assert.ok(
    assertion.prfOutput!.every((byte) => byte === 0),
    "new-device PRF zeroized after unlock",
  );
});

test("wrapper creation and unlock evaluate the SAME stable PRF eval salt", async () => {
  const root = new Uint8Array(32).fill(0x77);
  const fingerprint = await deriveWorkspaceRootFingerprint(root);
  const credentialIdB64 = "AQID";

  // The mock derives its PRF output from whatever eval salt the ceremony asks
  // for, exactly like a real authenticator. If wrapper creation and a later
  // login ever requested different salts, the real unwrap below would fail.
  const saltAwareCredentials = {
    get: async (options: CredentialRequestOptions) => {
      const publicKey = (options as { publicKey: PublicKeyCredentialRequestOptions })
        .publicKey;
      const evalFirst = (
        publicKey.extensions as
          | { prf?: { eval?: { first?: Uint8Array } } }
          | undefined
      )?.prf?.eval?.first;
      assert.ok(
        evalFirst && evalFirst.length > 0,
        "the ceremony must request a PRF eval salt",
      );
      const digest = await globalThis.crypto.subtle.digest(
        "SHA-256",
        evalFirst as unknown as BufferSource,
      );
      return prfCredential(new Uint8Array(digest), buffer(1, 2, 3));
    },
  } as unknown as CredentialsContainer;

  // Creation ceremony (as `runInitialSetup`/`addThisPasskey` do it).
  const creation = await authenticateWithPasskey({
    credentials: saltAwareCredentials,
    fetchFn: verifyFetch(),
  });
  assert.ok(creation.prfOutput);
  const wrapped = await wrapRootKey(
    creation.prfOutput!,
    root,
    generateRecoverySalt(),
    undefined,
    credentialIdB64,
    WORKSPACE_ROOT_KEY_SOURCE,
  );
  creation.prfOutput!.fill(0);
  const record: RecoveryWrapperRecord = {
    ...wrapped,
    credential_id_b64: credentialIdB64,
    label: "device",
    created_at_ms: 1,
    last_used_at_ms: null,
    revoked_at_ms: null,
  };

  // A later login ceremony must reproduce the same PRF output and unwrap.
  const login = await authenticateWithPasskey({
    credentials: saltAwareCredentials,
    fetchFn: verifyFetch(),
  });
  const unwrapped = await unwrapRootFromAssertion(login, [record], fingerprint);
  assert.deepEqual(unwrapped, root);
});

test("a pre-fix per-wrapper eval-salt wrapper fails closed, and the documented re-add migrates it", async () => {
  // The single-ceremony fix moved the PRF eval salt from each record's random
  // `salt_b64` to the stable workspace constant, so the PRF an authenticator
  // returns for an old wrapper differs from the constant-salt PRF (modelled
  // here by two different PRF byte strings). The old wrapper must fail closed
  // (never unlock with the wrong key), and the documented recovery-then-"Add
  // this device's passkey" path must rewrite a working wrapper under the same
  // root. This pins docs/workspace-recovery.md.
  const root = new Uint8Array(32).fill(0x7a);
  const fingerprint = await deriveWorkspaceRootFingerprint(root);
  const credentialIdB64 = "AQID";
  const legacyPerWrapperPrf = new Uint8Array(32).fill(0x0a);
  const stableConstantPrf = new Uint8Array(32).fill(0x0b);

  const legacyWrapped = await wrapRootKey(
    legacyPerWrapperPrf,
    root,
    generateRecoverySalt(),
    undefined,
    credentialIdB64,
    WORKSPACE_ROOT_KEY_SOURCE,
  );
  const legacyRecord: RecoveryWrapperRecord = {
    ...legacyWrapped,
    credential_id_b64: credentialIdB64,
    label: "legacy per-wrapper salt",
    created_at_ms: 1,
    last_used_at_ms: null,
    revoked_at_ms: null,
  };

  // The fixed constant-salt login produces a different PRF, so unwrap fails
  // closed rather than returning a wrong or partial root.
  await assert.rejects(
    unwrapRootFromAssertion(
      { credentialIdB64, prfOutput: stableConstantPrf.slice() },
      [legacyRecord],
      fingerprint,
    ),
    (error: unknown) =>
      error instanceof WorkspaceUnlockError && error.code === "unwrap_failed",
  );

  // Migration: recover with the offline code, then re-add the passkey, which
  // writes a NEW wrapper under the same stable root and the constant-salt PRF.
  const migratedWrapped = await wrapRootKey(
    stableConstantPrf,
    root,
    generateRecoverySalt(),
    undefined,
    credentialIdB64,
    WORKSPACE_ROOT_KEY_SOURCE,
  );
  const migratedRecord: RecoveryWrapperRecord = {
    ...migratedWrapped,
    credential_id_b64: credentialIdB64,
    label: "migrated device",
    created_at_ms: 2,
    last_used_at_ms: null,
    revoked_at_ms: null,
  };
  const migratedRoot = await unwrapRootFromAssertion(
    { credentialIdB64, prfOutput: stableConstantPrf.slice() },
    [migratedRecord],
    fingerprint,
  );
  assert.deepEqual(migratedRoot, root);
});
