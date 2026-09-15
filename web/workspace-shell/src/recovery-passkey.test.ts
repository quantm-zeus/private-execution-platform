import assert from "node:assert/strict";
import { test } from "node:test";

import { PasskeyAuthError } from "./passkey-auth.ts";
import { authenticateWithPrf } from "./recovery-passkey.ts";
import { toBase64 } from "./recovery-client.ts";

function credential(prfBytes: Uint8Array | null): unknown {
  return {
    id: "credential-id",
    rawId: new Uint8Array(32).fill(0x11).buffer,
    type: "public-key",
    response: {
      clientDataJSON: new Uint8Array([1]).buffer,
      authenticatorData: new Uint8Array([2]).buffer,
      signature: new Uint8Array([3]).buffer,
      userHandle: null,
    },
    getClientExtensionResults: () =>
      prfBytes ? { prf: { results: { first: prfBytes } } } : { prf: {} },
  };
}

function challengeResponse(): Response {
  return new Response(
    JSON.stringify({
      publicKey: { challenge: "AAAA", allowCredentials: [], rpId: "example.com" },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

test("authenticateWithPrf returns the credential id and PRF output and requests the salt", async () => {
  let captured: { publicKey: PublicKeyCredentialRequestOptions } | undefined;
  const credentials = {
    get: async (options: CredentialRequestOptions) => {
      captured = options as { publicKey: PublicKeyCredentialRequestOptions };
      return credential(new Uint8Array(32).fill(0x5a));
    },
  } as unknown as CredentialsContainer;
  const salt = new Uint8Array(32).fill(7);
  const fetchFn = (async (url: string) => {
    if (String(url).includes("challenge")) return challengeResponse();
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;

  const result = await authenticateWithPrf({ credentials, fetchFn, prfSalt: salt });
  assert.equal(result.credentialIdB64, toBase64(new Uint8Array(32).fill(0x11)));
  assert.deepEqual(result.prfOutput, new Uint8Array(32).fill(0x5a));
  const extensions = captured?.publicKey.extensions as
    | { prf?: { eval?: { first?: Uint8Array } } }
    | undefined;
  assert.deepEqual(extensions?.prf?.eval?.first, salt);
});

test("a credential without PRF yields null output, never a signature fallback", async () => {
  const credentials = {
    get: async () => credential(null),
  } as unknown as CredentialsContainer;
  const fetchFn = (async (url: string) => {
    if (String(url).includes("challenge")) return challengeResponse();
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;

  const result = await authenticateWithPrf({ credentials, fetchFn });
  assert.equal(result.prfOutput, null);
  assert.equal(result.credentialIdB64, toBase64(new Uint8Array(32).fill(0x11)));
});

test("authenticateWithPrf fails closed on unsupported, malformed and rejected paths", async () => {
  const fetchFn = (async () => challengeResponse()) as unknown as typeof fetch;

  await assert.rejects(
    authenticateWithPrf({ credentials: {} as CredentialsContainer, fetchFn }),
    (error: unknown) =>
      error instanceof PasskeyAuthError && error.code === "webauthn_unsupported",
  );

  const failingGet = {
    get: async () => {
      throw new Error("user cancelled");
    },
  } as unknown as CredentialsContainer;
  await assert.rejects(
    authenticateWithPrf({ credentials: failingGet, fetchFn }),
    (error: unknown) =>
      error instanceof PasskeyAuthError && error.code === "assertion_unavailable",
  );

  const rejectingVerify = (async (url: string) => {
    if (String(url).includes("challenge")) return challengeResponse();
    return new Response(null, { status: 401 });
  }) as unknown as typeof fetch;
  const credentials = {
    get: async () => credential(new Uint8Array(32).fill(1)),
  } as unknown as CredentialsContainer;
  await assert.rejects(
    authenticateWithPrf({ credentials, fetchFn: rejectingVerify }),
    (error: unknown) =>
      error instanceof PasskeyAuthError && error.code === "verification_rejected",
  );
});
