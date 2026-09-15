// WebAuthn PRF assertion for passkey-bound workspace recovery.
//
// A normal passkey assertion signature is authentication evidence, NOT key
// material: assertions vary and authenticator private keys are inaccessible.
// This module requests the WebAuthn PRF extension and returns its output only
// when the authenticator actually produced one; otherwise the caller falls back
// to the mandatory offline recovery code.
//
// The PRF output and any derived wrapping key never leave the browser.

import {
  PasskeyAuthError,
  buildRequestOptions,
  serializeAssertion,
  DEFAULT_CHALLENGE_URL,
  DEFAULT_VERIFY_URL,
  type PasskeyAuthOptions,
} from "./passkey-auth.ts";
import { extractPrfOutput } from "./recovery-wrapping.ts";

export interface PrfAssertionResult {
  /** Standard-base64 raw credential id of the credential that authenticated. */
  credentialIdB64: string;
  /** PRF output, or `null` when the authenticator did not return one. */
  prfOutput: Uint8Array | null;
}

export interface PrfAssertionOptions extends PasskeyAuthOptions {
  /** Restrict the ceremony to one credential (standard-base64 raw id). */
  allowCredentialB64?: string;
  /** PRF evaluation salt. When absent, PRF is not requested. */
  prfSalt?: Uint8Array;
}

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    out += BASE64_ALPHABET[(triple >> 18) & 63];
    out += BASE64_ALPHABET[(triple >> 12) & 63];
    out += i + 1 < bytes.length ? BASE64_ALPHABET[(triple >> 6) & 63] : "=";
    out += i + 2 < bytes.length ? BASE64_ALPHABET[triple & 63] : "=";
  }
  return out;
}

function fromBase64(value: string): Uint8Array {
  const clean = value.replace(/\s/g, "");
  const revLookup: Record<string, number> = {};
  for (let i = 0; i < 64; i++) revLookup[BASE64_ALPHABET[i]] = i;
  let valid = clean;
  if (clean.endsWith("==")) valid = clean.slice(0, -2);
  else if (clean.endsWith("=")) valid = clean.slice(0, -1);
  const out = new Uint8Array(Math.floor((valid.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let index = 0;
  for (const char of valid) {
    const mapped = revLookup[char];
    if (mapped === undefined) throw new PasskeyAuthError("challenge_malformed");
    acc = (acc << 6) | mapped;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/**
 * Authenticate with a passkey while requesting PRF evaluation, returning the
 * raw credential id and the PRF output (if any). Throws the same typed
 * `PasskeyAuthError` as the ordinary authentication path.
 */
export async function authenticateWithPrf(
  options: PrfAssertionOptions = {},
): Promise<PrfAssertionResult> {
  const fetchImpl = options.fetchFn ?? fetch;
  const container = options.credentials ?? globalThis.navigator?.credentials;
  if (!container || typeof container.get !== "function") {
    throw new PasskeyAuthError("webauthn_unsupported");
  }

  let challengeResponse: Response;
  try {
    challengeResponse = await fetchImpl(
      options.challengeUrl ?? DEFAULT_CHALLENGE_URL,
      {
        method: "POST",
        credentials: "same-origin",
        redirect: "error",
        headers: { Accept: "application/json" },
      },
    );
  } catch {
    throw new PasskeyAuthError("challenge_unavailable");
  }
  if (!challengeResponse.ok) {
    throw new PasskeyAuthError("challenge_unavailable", challengeResponse.status);
  }
  let body: unknown;
  try {
    body = await challengeResponse.json();
  } catch {
    throw new PasskeyAuthError("challenge_malformed");
  }
  const publicKey =
    body && typeof body === "object" && "publicKey" in body
      ? (body as { publicKey: unknown }).publicKey
      : body;
  const requestOptions = buildRequestOptions(publicKey);
  if (options.allowCredentialB64) {
    requestOptions.allowCredentials = [
      {
        type: "public-key",
        id: fromBase64(options.allowCredentialB64) as unknown as BufferSource,
      },
    ];
  }
  if (options.prfSalt && options.prfSalt.length > 0) {
    requestOptions.extensions = {
      ...(requestOptions.extensions ?? {}),
      prf: { eval: { first: options.prfSalt } },
    } as AuthenticationExtensionsClientInputs;
  }

  let assertion: Credential | null;
  try {
    assertion = await container.get({ publicKey: requestOptions });
  } catch {
    throw new PasskeyAuthError("assertion_unavailable");
  }
  if (!assertion) {
    throw new PasskeyAuthError("assertion_unavailable");
  }
  const publicKeyCredential = assertion as PublicKeyCredential;
  const credentialIdB64 = toBase64(new Uint8Array(publicKeyCredential.rawId));
  const prfOutput = extractPrfOutput(assertion);

  let response: Response;
  try {
    response = await fetchImpl(options.verifyUrl ?? DEFAULT_VERIFY_URL, {
      method: "POST",
      credentials: "same-origin",
      redirect: "error",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(serializeAssertion(publicKeyCredential)),
    });
  } catch {
    throw new PasskeyAuthError("verification_rejected");
  }
  if (!response.ok) {
    throw new PasskeyAuthError("verification_rejected", response.status);
  }
  return { credentialIdB64, prfOutput };
}
