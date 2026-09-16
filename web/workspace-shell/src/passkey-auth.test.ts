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
import { workspacePrfEvalSalt } from "./recovery-wrapping.ts";

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

test("buildCreationOptions preserves a server-supplied PRF configuration", () => {
  const serverPrf = { eval: { first: "AQIDBAUGBwgJCgsMDQ4PEA" } };
  const options = buildCreationOptions({
    rp: { id: "evergreen.foresift.tech" },
    user: { id: "AQID", name: "owner", displayName: "Owner" },
    challenge: "BwgJ",
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    extensions: { credProps: true, prf: serverPrf },
  });
  const extensions = options.extensions as
    | { prf?: unknown; credProps?: unknown }
    | undefined;
  // A server-supplied evaluation salt must round-trip unchanged and PRF must
  // stay enabled; clobbering it would silently drop the server's PRF config.
  assert.deepEqual(extensions?.prf, serverPrf);
  assert.equal(extensions?.credProps, true);

  // A malformed (non-object) server value must not disable PRF.
  const malformed = buildCreationOptions({
    rp: { id: "evergreen.foresift.tech" },
    user: { id: "AQID", name: "owner", displayName: "Owner" },
    challenge: "BwgJ",
    pubKeyCredParams: [],
    extensions: { prf: "nonsense" },
  });
  assert.deepEqual(
    (malformed.extensions as { prf?: unknown } | undefined)?.prf,
    {},
  );
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

// ---------------------------------------------------------------------------
// Single-ceremony login contract (GPT-5.6 Sol/high Root-Key V2 remediation).
//
// The normal configured login must be EXACTLY ONE navigator.credentials.get()
// that both authenticates (signature only, sent to the server) and evaluates
// PRF against the stable workspace salt for the local unwrap.
// ---------------------------------------------------------------------------

function challengeResponse(): Response {
  return new Response(
    JSON.stringify({
      publicKey: {
        challenge: "AQID",
        rpId: "example.com",
        allowCredentials: [
          { id: "AQID", type: "public-key" },
          { id: "BAUG", type: "public-key" },
        ],
      },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

/** A WebAuthn assertion whose PRF extension returns `prfBytes`. */
function prfAssertion(prfBytes: Uint8Array): PublicKeyCredential {
  return {
    id: "cred",
    rawId: buffer(1, 2, 3),
    type: "public-key",
    response: {
      clientDataJSON: buffer(4, 5),
      authenticatorData: buffer(6),
      // Deliberately distinctive: it must never surface as key material.
      signature: buffer(0xde, 0xad, 0xbe, 0xef),
      userHandle: null,
    },
    getClientExtensionResults: () =>
      ({ prf: { results: { first: prfBytes } } }),
  } as unknown as PublicKeyCredential;
}

test("normal login performs exactly one ceremony and returns stable PRF output", async () => {
  const prfBytes = new Uint8Array(32).fill(0x5a);
  let getCalls = 0;
  let captured: PublicKeyCredentialRequestOptions | undefined;
  const credentials = {
    get: async (options: CredentialRequestOptions) => {
      getCalls += 1;
      captured = (options as { publicKey: PublicKeyCredentialRequestOptions })
        .publicKey;
      return prfAssertion(prfBytes);
    },
  } as unknown as CredentialsContainer;
  const urls: string[] = [];
  const fetchFn = (async (url: string) => {
    urls.push(String(url));
    if (String(url).includes("challenge")) return challengeResponse();
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;

  const result = await authenticateWithPasskey({ credentials, fetchFn });

  assert.equal(getCalls, 1, "one login is exactly one credentials.get()");
  assert.deepEqual(urls, ["/internal/auth/challenge", "/internal/auth/verify"]);
  assert.equal(result.credentialIdB64, "AQID");
  assert.deepEqual(result.prfOutput, prfBytes);
  // The single ceremony evaluates the stable, public workspace eval salt, so the
  // returned PRF output can unwrap whichever wrapper matches the returned id.
  const extensions = captured?.extensions as
    | { prf?: { eval?: { first?: Uint8Array } } }
    | undefined;
  assert.deepEqual(extensions?.prf?.eval?.first, workspacePrfEvalSalt());
  assert.ok((extensions?.prf?.eval?.first?.length ?? 0) > 0);
});

test("PRF-unavailable login authenticates once, returns null and never prompts again", async () => {
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
  const fetchFn = (async (url: string) => {
    if (String(url).includes("challenge")) return challengeResponse();
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;

  const result = await authenticateWithPasskey({ credentials, fetchFn });
  assert.equal(result.prfOutput, null);
  assert.equal(getCalls, 1, "PRF absence must not trigger a second ceremony");
});

test("the assertion signature is never returned as key material", async () => {
  const prfBytes = new Uint8Array(32).fill(0x33);
  const credentials = {
    get: async () => prfAssertion(prfBytes),
  } as unknown as CredentialsContainer;
  const fetchFn = (async (url: string) => {
    if (String(url).includes("challenge")) return challengeResponse();
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;

  const result = await authenticateWithPasskey({ credentials, fetchFn });
  assert.deepEqual(result.prfOutput, prfBytes);
  assert.notDeepEqual(result.prfOutput, new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
});

test("authenticateWithPasskey zeroizes its PRF copy only on a rejected verify", async () => {
  const prf = new Uint8Array(32).fill(0x77);
  const credentials = {
    get: async () => prfAssertion(prf),
  } as unknown as CredentialsContainer;
  const successFetch = (async (url: string) => {
    if (String(url).includes("challenge")) return challengeResponse();
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
  const failingFetch = (async (url: string) => {
    if (String(url).includes("challenge")) return challengeResponse();
    return new Response(null, { status: 401 });
  }) as unknown as typeof fetch;

  // `extractPrfOutput` copies the authenticator bytes, so zeroization happens on
  // that internal copy. Observe it at the buffer API boundary without exporting
  // key material.
  const originalFill = Uint8Array.prototype.fill;
  let zeroized = 0;
  Uint8Array.prototype.fill = function (
    this: Uint8Array,
    value: number,
    start?: number,
    end?: number,
  ): Uint8Array {
    if (value === 0 && this.length === 32 && this[0] === 0x77) zeroized += 1;
    return originalFill.call(this, value, start, end);
  } as typeof Uint8Array.prototype.fill;

  try {
    // A successful verify returns the PRF to the caller, which owns it for the
    // local unwrap: the client must NOT zeroize it here.
    const ok = await authenticateWithPasskey({
      credentials,
      fetchFn: successFetch,
    });
    assert.equal(zeroized, 0, "a successful verify must not zeroize the returned PRF");
    // Test-owned cleanup after the assertion; counted so the failure branch
    // below still proves the client (not the test) zeroizes its own copy.
    ok.prfOutput?.fill(0);
    assert.equal(zeroized, 1);

    // A rejected verify must zeroize the client's PRF copy before throwing.
    await assert.rejects(
      authenticateWithPasskey({ credentials, fetchFn: failingFetch }),
      (error: unknown) =>
        error instanceof PasskeyAuthError && error.code === "verification_rejected",
    );
    assert.equal(zeroized, 2, "a rejected verify must zeroize the PRF copy");
  } finally {
    Uint8Array.prototype.fill = originalFill;
  }
});

test("authenticateWithPasskey fails closed on unsupported and rejected paths", async () => {
  const fetchFn = (async () => challengeResponse()) as unknown as typeof fetch;
  await assert.rejects(
    authenticateWithPasskey({ credentials: {} as CredentialsContainer, fetchFn }),
    (error: unknown) =>
      error instanceof PasskeyAuthError && error.code === "webauthn_unsupported",
  );

  const failingGet = {
    get: async () => {
      throw new Error("user cancelled");
    },
  } as unknown as CredentialsContainer;
  await assert.rejects(
    authenticateWithPasskey({ credentials: failingGet, fetchFn }),
    (error: unknown) =>
      error instanceof PasskeyAuthError && error.code === "assertion_unavailable",
  );
});
