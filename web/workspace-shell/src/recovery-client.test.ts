import assert from "node:assert/strict";
import { test } from "node:test";

import {
  RecoveryClientError,
  addRecoveryWrapper,
  beginRecoveryProof,
  bootstrapWorkspaceIdentity,
  fetchRecoveryWrappers,
  fetchWorkspaceIdentity,
  parseRecoveryWrappers,
  parseWorkspaceIdentity,
  revokeRecoveryWrapper,
  toBase64,
  touchRecoveryWrapper,
  unwrapWithPrfOutput,
} from "./recovery-client.ts";
import {
  generateRecoverySalt,
  generateWorkspaceRootKey,
  RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2,
  wrapRootKey,
} from "./recovery-wrapping.ts";

const VALID_RECORD = {
  credential_id_b64: toBase64(new Uint8Array(32).fill(1)),
  label: "Laptop",
  version: 1,
  algorithm: "HKDF-SHA256/AES-256-GCM",
  key_source: "workspace_root_v2",
  salt_b64: toBase64(new Uint8Array(32).fill(2)),
  iv_b64: toBase64(new Uint8Array(12).fill(3)),
  wrapped_root_key_b64: toBase64(new Uint8Array(48).fill(4)),
  created_at_ms: 5,
  last_used_at_ms: null,
  revoked_at_ms: null,
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("parseRecoveryWrappers rejects malformed containers and skips bad records", () => {
  const parsed = parseRecoveryWrappers({ wrappers: [VALID_RECORD] });
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].label, "Laptop");
  assert.equal(parsed[0].last_used_at_ms, null);

  for (const bad of [null, {}, { wrappers: "x" }]) {
    assert.throws(
      () => parseRecoveryWrappers(bad),
      (error: unknown) =>
        error instanceof RecoveryClientError && error.code === "recovery_malformed",
    );
  }

  // A single malformed or unknown-key_source record must not disable the valid
  // credentials beside it (the offline recovery code remains the fallback).
  const mixed = parseRecoveryWrappers({
    wrappers: [
      { ...VALID_RECORD, version: 2 },
      VALID_RECORD,
      { ...VALID_RECORD, key_source: "root_key_v2" },
      { ...VALID_RECORD, key_source: "unlock_secret_v1" },
      { ...VALID_RECORD, credential_id_b64: "" },
      { ...VALID_RECORD, created_at_ms: "soon" },
    ],
  });
  assert.equal(mixed.length, 1);
  assert.equal(mixed[0].label, "Laptop");

  // An all-invalid list yields an empty list, never a thrown parse. Legacy
  // `unlock_secret_v1` records are migration data, not stable-root wrappers.
  assert.deepEqual(
    parseRecoveryWrappers({
      wrappers: [
        { ...VALID_RECORD, version: 2 },
        { ...VALID_RECORD, key_source: "unlock_secret_v1" },
      ],
    }),
    [],
  );
});

test("parseRecoveryWrappers skips records with a wrong algorithm or decoded lengths", () => {
  const badAlgorithm = { ...VALID_RECORD, algorithm: "plain" };
  const shortSalt = {
    ...VALID_RECORD,
    salt_b64: toBase64(new Uint8Array(16).fill(2)),
  };
  const shortIv = {
    ...VALID_RECORD,
    iv_b64: toBase64(new Uint8Array(8).fill(3)),
  };
  const shortCiphertext = {
    ...VALID_RECORD,
    wrapped_root_key_b64: toBase64(new Uint8Array(32).fill(4)),
  };
  const parsed = parseRecoveryWrappers({
    wrappers: [
      badAlgorithm,
      shortSalt,
      shortIv,
      shortCiphertext,
      VALID_RECORD,
    ],
  });
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].label, "Laptop");
  // All malformed records are dropped, never thrown.
  assert.deepEqual(
    parseRecoveryWrappers({ wrappers: [badAlgorithm, shortSalt, shortIv, shortCiphertext] }),
    [],
  );
});

test("fetchRecoveryWrappers classifies auth, conflict and network failures", async () => {
  const ok = await fetchRecoveryWrappers({
    fetchFn: (async () =>
      jsonResponse({ wrappers: [VALID_RECORD] })) as unknown as typeof fetch,
  });
  assert.equal(ok.length, 1);

  await assert.rejects(
    fetchRecoveryWrappers({
      fetchFn: (async () => jsonResponse({}, 401)) as unknown as typeof fetch,
    }),
    (error: unknown) =>
      error instanceof RecoveryClientError &&
      error.code === "recovery_unauthorized",
  );
  await assert.rejects(
    fetchRecoveryWrappers({
      fetchFn: (async () => {
        throw new TypeError("down");
      }) as unknown as typeof fetch,
    }),
    (error: unknown) =>
      error instanceof RecoveryClientError &&
      error.code === "recovery_unavailable",
  );
});

test("beginRecoveryProof decrypts the sealed challenge and returns a proof", async () => {
  const sealed = new Uint8Array(97).fill(9);
  const proof = new Uint8Array(32).fill(7);
  const expectedProofB64 = toBase64(proof);
  const result = await beginRecoveryProof(
    (input) => {
      assert.deepEqual(input, sealed);
      return proof;
    },
    {
      fetchFn: (async () =>
        jsonResponse({
          challenge_id: "a".repeat(32),
          sealed_challenge_b64: toBase64(sealed),
          expires_in_ms: 1000,
        })) as unknown as typeof fetch,
    },
  );
  assert.equal(result.challengeId, "a".repeat(32));
  assert.equal(result.proofB64, expectedProofB64);
  // The runtime zeroizes the decrypted nonce buffer before returning.
  assert.ok(proof.every((byte) => byte === 0));

  await assert.rejects(
    beginRecoveryProof(
      () => {
        throw new Error("no key");
      },
      {
        fetchFn: (async () =>
          jsonResponse({
            challenge_id: "a".repeat(32),
            sealed_challenge_b64: toBase64(sealed),
            expires_in_ms: 1000,
          })) as unknown as typeof fetch,
      },
    ),
    (error: unknown) =>
      error instanceof RecoveryClientError && error.code === "recovery_rejected",
  );
});

test("beginRecoveryProof rejects a challenge plaintext that is not 32 bytes", async () => {
  for (const length of [0, 16, 64]) {
    await assert.rejects(
      beginRecoveryProof(() => new Uint8Array(length).fill(1), {
        fetchFn: (async () =>
          jsonResponse({
            challenge_id: "a".repeat(32),
            sealed_challenge_b64: toBase64(new Uint8Array(97).fill(9)),
            expires_in_ms: 1000,
          })) as unknown as typeof fetch,
      }),
      (error: unknown) =>
        error instanceof RecoveryClientError && error.code === "recovery_rejected",
    );
  }
});

test("add/revoke/touch send the expected wire body", async () => {
  let body = "";
  const fetchFn = (async (_url: string, init?: RequestInit) => {
    body = String(init?.body ?? "");
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;

  await addRecoveryWrapper(
    {
      challengeId: "challenge",
      proofB64: "proof",
      credentialIdB64: "credential",
      label: "Device",
      record: {
        version: 1,
        algorithm: "HKDF-SHA256/AES-256-GCM",
        key_source: "workspace_root_v2",
        salt_b64: "salt",
        iv_b64: "iv",
        wrapped_root_key_b64: "wrapped",
      },
    },
    { fetchFn },
  );
  const add = JSON.parse(body);
  assert.equal(add.challenge_id, "challenge");
  assert.equal(add.wrapper.key_source, "workspace_root_v2");
  assert.equal(add.wrapper.credential_id_b64, "credential");

  await revokeRecoveryWrapper(
    { challengeId: "challenge", proofB64: "proof", credentialIdB64: "credential" },
    { fetchFn },
  );
  assert.equal(JSON.parse(body).credential_id_b64, "credential");

  await touchRecoveryWrapper(
    { challengeId: "challenge", proofB64: "proof", credentialIdB64: "credential" },
    { fetchFn },
  );
  assert.equal(JSON.parse(body).credential_id_b64, "credential");
  assert.equal(JSON.parse(body).proof_b64, "proof");
});

test("unwrapWithPrfOutput roundtrips a wrapped secret", async () => {
  const root = generateWorkspaceRootKey();
  const prf = new Uint8Array(32).fill(0x5a);
  const wrapped = await wrapRootKey(
    prf,
    root,
    generateRecoverySalt(),
    undefined,
    undefined,
    RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2,
  );
  const recovered = await unwrapWithPrfOutput(prf, wrapped);
  assert.deepEqual(recovered, root);

  const wrong = new Uint8Array(32).fill(0x5b);
  await assert.rejects(unwrapWithPrfOutput(wrong, wrapped));

  // A legacy v1 record is never unwrapped as a stable root, even with the
  // correct PRF output.
  await assert.rejects(
    unwrapWithPrfOutput(prf, { ...wrapped, key_source: "unlock_secret_v1" }),
  );
});

test("a wrapper's credential id is bound into the AEAD tag", async () => {
  const root = generateWorkspaceRootKey();
  const prf = new Uint8Array(32).fill(0x5a);
  const credentialId = toBase64(new Uint8Array(32).fill(7));
  const wrapped = await wrapRootKey(
    prf,
    root,
    generateRecoverySalt(),
    undefined,
    credentialId,
    RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2,
  );

  // The same PRF and record still unwrap for the owning credential.
  const recovered = await unwrapWithPrfOutput(prf, {
    ...wrapped,
    credential_id_b64: credentialId,
  });
  assert.deepEqual(recovered, root);

  // Reassigning the record to a different credential (or omitting the id) must
  // fail authentication, not silently unwrap.
  await assert.rejects(
    unwrapWithPrfOutput(prf, {
      ...wrapped,
      credential_id_b64: toBase64(new Uint8Array(32).fill(8)),
    }),
  );
  await assert.rejects(unwrapWithPrfOutput(prf, wrapped));
});

test("parseWorkspaceIdentity accepts configured public metadata only", () => {
  const publicKey = toBase64(new Uint8Array(32).fill(0x21));
  const fingerprint = toBase64(new Uint8Array(32).fill(0x99));
  const parsed = parseWorkspaceIdentity({
    configured: true,
    version: 1,
    public_key_b64: publicKey,
    fingerprint_b64: fingerprint,
  });
  assert.equal(parsed.configured, true);
  assert.equal(parsed.publicKeyB64, publicKey);
  assert.equal(parsed.fingerprintB64, fingerprint);

  const unconfigured = parseWorkspaceIdentity({ configured: false });
  assert.equal(unconfigured.configured, false);
  assert.equal(unconfigured.publicKeyB64, null);

  for (const bad of [
    null,
    "x",
    { configured: true },
    { configured: true, version: 1, public_key_b64: "AA==", fingerprint_b64: fingerprint },
    { configured: true, version: 1, public_key_b64: publicKey, fingerprint_b64: "AA==" },
  ]) {
    assert.throws(
      () => parseWorkspaceIdentity(bad),
      (error: unknown) =>
        error instanceof RecoveryClientError && error.code === "recovery_malformed",
    );
  }
});

test("fetchWorkspaceIdentity classifies auth and network failures", async () => {
  const identity = await fetchWorkspaceIdentity({
    fetchFn: (async () =>
      jsonResponse({
        configured: true,
        version: 1,
        public_key_b64: toBase64(new Uint8Array(32).fill(0x21)),
        fingerprint_b64: toBase64(new Uint8Array(32).fill(0x99)),
      })) as unknown as typeof fetch,
  });
  assert.equal(identity.configured, true);

  await assert.rejects(
    fetchWorkspaceIdentity({
      fetchFn: (async () => jsonResponse({}, 401)) as unknown as typeof fetch,
    }),
    (error: unknown) =>
      error instanceof RecoveryClientError && error.code === "recovery_unauthorized",
  );
  await assert.rejects(
    fetchWorkspaceIdentity({
      fetchFn: (async () => {
        throw new Error("offline");
      }) as unknown as typeof fetch,
    }),
    (error: unknown) =>
      error instanceof RecoveryClientError && error.code === "recovery_unavailable",
  );
});

test("bootstrapWorkspaceIdentity uploads only the public key and wrappers", async () => {
  let body = "";
  let method = "";
  const publicKey = toBase64(new Uint8Array(32).fill(0x21));
  const record = {
    version: 1,
    algorithm: "HKDF-SHA256/AES-256-GCM",
    key_source: "workspace_root_v2",
    salt_b64: toBase64(new Uint8Array(32).fill(2)),
    iv_b64: toBase64(new Uint8Array(12).fill(3)),
    wrapped_root_key_b64: toBase64(new Uint8Array(48).fill(4)),
  };
  const fetchFn = (async (_url: string, init?: RequestInit) => {
    body = String(init?.body ?? "");
    method = String(init?.method ?? "");
    return jsonResponse({
      configured: true,
      version: 1,
      public_key_b64: publicKey,
      fingerprint_b64: toBase64(new Uint8Array(32).fill(0x99)),
    });
  }) as unknown as typeof fetch;

  const identity = await bootstrapWorkspaceIdentity(
    {
      version: 1,
      publicKeyB64: publicKey,
      wrappers: [
        {
          credentialIdB64: toBase64(new Uint8Array(32).fill(1)),
          label: "This device",
          record,
        },
      ],
    },
    { fetchFn },
  );
  assert.equal(method, "POST");
  assert.equal(identity.configured, true);
  const sent = JSON.parse(body);
  assert.equal(sent.public_key, publicKey);
  assert.equal(sent.wrappers.length, 1);
  assert.equal(sent.wrappers[0].key_source, "workspace_root_v2");
  // The bootstrap body must never carry plaintext secret material.
  for (const forbidden of [
    "root_secret",
    "recovery_code",
    "prf_output",
    "unwrap_key",
    "private_key",
  ]) {
    assert.equal(sent[forbidden], undefined, `bootstrap must not send ${forbidden}`);
    assert.equal(sent.wrappers[0][forbidden], undefined);
  }
});
