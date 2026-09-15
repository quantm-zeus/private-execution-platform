// Pure-Node tests for the shell passkey client. Run with `node --test`.
//
// These exercise the JSON <-> DOM conversion and the same-origin request shape
// without a browser. They are deliberately credential-free: every "credential"
// is a synthetic object, and no real WebAuthn material is involved.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  authenticateWithPasskey,
  buildCreationOptions,
  buildRequestOptions,
  enrollPasskey,
  PasskeyAuthError,
  serializeAssertion,
  serializeAttestation,
} from "./passkey-auth.ts";

const bytes = (...values: number[]): Uint8Array => new Uint8Array(values);
const buffer = (...values: number[]): ArrayBuffer =>
  bytes(...values).buffer as ArrayBuffer;

function fakeAssertion(): PublicKeyCredential {
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
  } as unknown as PublicKeyCredential;
}

function fakeAttestation(): PublicKeyCredential {
  return {
    id: "cred",
    rawId: buffer(1, 2, 3),
    type: "public-key",
    response: {
      attestationObject: buffer(9, 10),
      clientDataJSON: buffer(4, 5),
    },
  } as unknown as PublicKeyCredential;
}

test("buildRequestOptions decodes base64url challenge and credential ids", () => {
  const options = buildRequestOptions({
    challenge: "AQID",
    rpId: "evergreen.foresift.tech",
    timeout: 60000,
    userVerification: "required",
    allowCredentials: [{ id: "BAUG", type: "public-key" }],
  });
  assert.deepEqual(Array.from(options.challenge as Uint8Array), [1, 2, 3]);
  assert.equal(options.rpId, "evergreen.foresift.tech");
  assert.equal(options.userVerification, "required");
  assert.deepEqual(
    Array.from(options.allowCredentials![0].id as Uint8Array),
    [4, 5, 6],
  );
});

test("buildCreationOptions decodes user id and excludes credentials", () => {
  const options = buildCreationOptions({
    rp: { id: "evergreen.foresift.tech", name: "Evergreen" },
    user: { id: "AQID", name: "owner", displayName: "Owner" },
    challenge: "BwgJ",
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    excludeCredentials: [{ id: "BAUG", type: "public-key" }],
  });
  assert.deepEqual(Array.from(options.user.id as Uint8Array), [1, 2, 3]);
  assert.equal(options.rp.id, "evergreen.foresift.tech");
  assert.deepEqual(Array.from(options.challenge as Uint8Array), [7, 8, 9]);
  assert.deepEqual(
    Array.from(options.excludeCredentials![0].id as Uint8Array),
    [4, 5, 6],
  );
});

test("buildCreationOptions requests PRF at registration and preserves server extensions", () => {
  const options = buildCreationOptions({
    rp: { id: "evergreen.foresift.tech", name: "Evergreen" },
    user: { id: "AQID", name: "owner", displayName: "Owner" },
    challenge: "BwgJ",
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    extensions: { credProps: true },
  });
  const extensions = options.extensions as
    | { prf?: unknown; credProps?: unknown }
    | undefined;
  // The PRF extension is requested at registration so a later recovery
  // assertion can evaluate it; an authenticator without support ignores it and
  // enrollment still succeeds.
  assert.deepEqual(extensions?.prf, {});
  assert.equal(extensions?.credProps, true);

  // With no server extensions, PRF is still requested.
  const bare = buildCreationOptions({
    rp: { id: "evergreen.foresift.tech" },
    user: { id: "AQID", name: "owner", displayName: "Owner" },
    challenge: "BwgJ",
    pubKeyCredParams: [],
  });
  assert.deepEqual((bare.extensions as { prf?: unknown } | undefined)?.prf, {});
});

test("buildRequestOptions rejects a malformed challenge", () => {
  assert.throws(
    () => buildRequestOptions({ challenge: 42 }),
    (error: unknown) =>
      error instanceof PasskeyAuthError && error.code === "challenge_malformed",
  );
});

test("serializeAssertion and serializeAttestation emit base64url bytes", () => {
  assert.deepEqual(serializeAssertion(fakeAssertion()), {
    id: "cred",
    rawId: "AQID",
    type: "public-key",
    response: {
      clientDataJSON: "BAU",
      authenticatorData: "Bg",
      signature: "Bwg",
      userHandle: null,
    },
  });
  assert.deepEqual(serializeAttestation(fakeAttestation()), {
    id: "cred",
    rawId: "AQID",
    type: "public-key",
    response: { attestationObject: "CQo", clientDataJSON: "BAU" },
  });
});

test("authenticateWithPasskey posts the assertion to the same-origin verify route", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchFn = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init: init ?? {} });
    if (url.includes("/challenge")) {
      return new Response(
        JSON.stringify({
          publicKey: {
            challenge: "AQID",
            rpId: "example.com",
            allowCredentials: [{ id: "BAUG", type: "public-key" }],
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
  const credentials = {
    get: async () => fakeAssertion(),
  } as unknown as CredentialsContainer;

  await authenticateWithPasskey({ fetchFn, credentials });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "/internal/auth/challenge");
  assert.equal(calls[0].init.credentials, "same-origin");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(calls[1].url, "/internal/auth/verify");
  assert.equal(calls[1].init.credentials, "same-origin");
  assert.equal(calls[1].init.redirect, "error");
  const authHeaders = calls[1].init.headers as Record<string, string>;
  assert.equal(authHeaders["Content-Type"], "application/json");
  assert.equal(authHeaders["x-evergreen-enroll-secret"], undefined);
  const body = JSON.parse(String(calls[1].init.body)) as {
    response: { signature: string };
  };
  assert.equal(body.response.signature, "Bwg");
});

test("authenticateWithPasskey fails closed when the challenge is unavailable", async () => {
  const fetchFn = (async () =>
    new Response("nope", { status: 503 })) as unknown as typeof fetch;
  const credentials = {
    get: async () => fakeAssertion(),
  } as unknown as CredentialsContainer;
  await assert.rejects(
    () => authenticateWithPasskey({ fetchFn, credentials }),
    (error: unknown) =>
      error instanceof PasskeyAuthError && error.code === "challenge_unavailable",
  );
});

test("enrollPasskey carries the operator secret only to the enrollment routes", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchFn = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init: init ?? {} });
    if (url.includes("/register/challenge")) {
      return new Response(
        JSON.stringify({
          publicKey: {
            rp: { id: "example.com", name: "Example" },
            user: { id: "AQID", name: "owner", displayName: "Owner" },
            challenge: "AQID",
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
  const credentials = {
    create: async () => fakeAttestation(),
  } as unknown as CredentialsContainer;

  await enrollPasskey("operator-bootstrap-secret", { fetchFn, credentials });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "/internal/auth/register/challenge");
  assert.equal(calls[1].url, "/internal/auth/register/verify");
  for (const call of calls) {
    assert.equal(call.init.credentials, "same-origin");
    assert.equal(call.init.redirect, "error");
    const headers = call.init.headers as Record<string, string>;
    assert.equal(headers["x-evergreen-enroll-secret"], "operator-bootstrap-secret");
  }
  const verifyHeaders = calls[1].init.headers as Record<string, string>;
  assert.equal(verifyHeaders["Content-Type"], "application/json");
  assert.deepEqual(
    JSON.parse(String(calls[1].init.body)),
    serializeAttestation(fakeAttestation()),
  );
  await assert.rejects(() => enrollPasskey("", { fetchFn, credentials }));
});
