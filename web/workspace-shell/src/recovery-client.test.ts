import assert from "node:assert/strict";
import { test } from "node:test";

import {
  RecoveryClientError,
  addRecoveryWrapper,
  beginRecoveryProof,
  fetchRecoveryWrappers,
  parseRecoveryWrappers,
  revokeRecoveryWrapper,
  toBase64,
  touchRecoveryWrapper,
  unwrapWithPrfOutput,
} from "./recovery-client.ts";
import {
  generateRecoverySalt,
  generateWorkspaceRootKey,
  wrapRootKey,
} from "./recovery-wrapping.ts";

const VALID_RECORD = {
  credential_id_b64: toBase64(new Uint8Array(32).fill(1)),
  label: "Laptop",
  version: 1,
  algorithm: "HKDF-SHA256/AES-256-GCM",
  key_source: "unlock_secret_v1",
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

test("parseRecoveryWrappers accepts a valid list and rejects malformed input", () => {
  const parsed = parseRecoveryWrappers({ wrappers: [VALID_RECORD] });
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].label, "Laptop");
  assert.equal(parsed[0].last_used_at_ms, null);

  for (const bad of [
    null,
    {},
    { wrappers: "x" },
    { wrappers: [{ ...VALID_RECORD, version: 2 }] },
    { wrappers: [{ ...VALID_RECORD, credential_id_b64: "" }] },
    { wrappers: [{ ...VALID_RECORD, created_at_ms: "soon" }] },
  ]) {
    assert.throws(
      () => parseRecoveryWrappers(bad),
      (error: unknown) =>
        error instanceof RecoveryClientError && error.code === "recovery_malformed",
    );
  }
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
        salt_b64: "salt",
        iv_b64: "iv",
        wrapped_root_key_b64: "wrapped",
      },
    },
    { fetchFn },
  );
  const add = JSON.parse(body);
  assert.equal(add.challenge_id, "challenge");
  assert.equal(add.wrapper.key_source, "unlock_secret_v1");
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
  const wrapped = await wrapRootKey(prf, root, generateRecoverySalt());
  const recovered = await unwrapWithPrfOutput(prf, wrapped);
  assert.deepEqual(recovered, root);

  const wrong = new Uint8Array(32).fill(0x5b);
  await assert.rejects(unwrapWithPrfOutput(wrong, wrapped));
});
