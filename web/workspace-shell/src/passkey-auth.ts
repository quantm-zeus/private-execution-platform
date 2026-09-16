// Browser passkey (WebAuthn) client for the clear workspace shell.
//
// This module is the only place the cleartext shell talks to the private
// authentication boundary (`/internal/auth/*`). Invariants:
//
// - Same-origin credentials only. The perimeter session and the `__Host-`
//   authentication cookies depend on `credentials: "same-origin"`.
// - No persistence. Nothing is written to storage; the server session lives in
//   an HttpOnly cookie the shell cannot read.
// - No leakage. Credential material and the operator enrollment secret are
//   never logged and never interpolated into errors.
// - Fail closed. A missing WebAuthn API, a malformed challenge or a non-2xx
//   response throws a typed error; the caller must keep the workspace locked.

/** Why a passkey operation could not complete. Deliberately transport-level. */
export type PasskeyAuthErrorCode =
  | "webauthn_unsupported"
  | "challenge_unavailable"
  | "challenge_malformed"
  | "assertion_unavailable"
  | "verification_rejected"
  | "enrollment_unavailable"
  | "enrollment_rejected";

export class PasskeyAuthError extends Error {
  readonly code: PasskeyAuthErrorCode;
  readonly status: number | undefined;

  constructor(code: PasskeyAuthErrorCode, status?: number) {
    // The message is intentionally generic: it must never carry credential
    // material, the challenge, or the operator enrollment secret.
    super("passkey authentication unavailable");
    this.name = "PasskeyAuthError";
    this.code = code;
    this.status = status;
  }
}

export interface PasskeyAuthOptions {
  challengeUrl?: string;
  verifyUrl?: string;
  fetchFn?: typeof fetch;
  credentials?: CredentialsContainer;
}

export interface PasskeyEnrollmentOptions extends PasskeyAuthOptions {
  registerChallengeUrl?: string;
  registerVerifyUrl?: string;
}

export const DEFAULT_CHALLENGE_URL = "/internal/auth/challenge";
export const DEFAULT_VERIFY_URL = "/internal/auth/verify";
export const DEFAULT_REGISTER_CHALLENGE_URL = "/internal/auth/register/challenge";
export const DEFAULT_REGISTER_VERIFY_URL = "/internal/auth/register/verify";
export const ENROLLMENT_SECRET_HEADER = "x-evergreen-enroll-secret";

export interface SerializedAssertion {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
}

export interface SerializedAttestation {
  id: string;
  rawId: string;
  type: string;
  response: {
    attestationObject: string;
    clientDataJSON: string;
  };
}

function decodeBase64Url(value: unknown): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new PasskeyAuthError("challenge_malformed");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded =
    normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new PasskeyAuthError("challenge_malformed");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function encodeBase64Url(value: ArrayBuffer | Uint8Array): string {
  const view = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (let i = 0; i < view.length; i++) {
    binary += String.fromCharCode(view[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function credentialDescriptors(
  input: unknown,
): PublicKeyCredentialDescriptor[] {
  if (!Array.isArray(input)) return [];
  return input.map((entry) => {
    if (!entry || typeof entry !== "object") {
      throw new PasskeyAuthError("challenge_malformed");
    }
    const descriptor = entry as { id?: unknown; transports?: unknown };
    return {
      type: "public-key",
      id: decodeBase64Url(descriptor.id),
      ...(Array.isArray(descriptor.transports)
        ? { transports: descriptor.transports as AuthenticatorTransport[] }
        : {}),
    } as PublicKeyCredentialDescriptor;
  });
}

/** Convert the server's `RequestChallengeResponse.publicKey` JSON to DOM options. */
export function buildRequestOptions(
  publicKey: unknown,
): PublicKeyCredentialRequestOptions {
  if (!publicKey || typeof publicKey !== "object") {
    throw new PasskeyAuthError("challenge_malformed");
  }
  const source = publicKey as {
    challenge?: unknown;
    rpId?: unknown;
    timeout?: unknown;
    userVerification?: unknown;
    allowCredentials?: unknown;
    extensions?: unknown;
  };
  const options: PublicKeyCredentialRequestOptions = {
    challenge: decodeBase64Url(source.challenge),
    allowCredentials: credentialDescriptors(source.allowCredentials),
  } as PublicKeyCredentialRequestOptions;
  if (typeof source.rpId === "string") options.rpId = source.rpId;
  if (typeof source.timeout === "number") options.timeout = source.timeout;
  if (typeof source.userVerification === "string") {
    options.userVerification =
      source.userVerification as UserVerificationRequirement;
  }
  if (source.extensions && typeof source.extensions === "object") {
    options.extensions = source.extensions as AuthenticationExtensionsClientInputs;
  }
  return options;
}

/** Convert the server's `CreationChallengeResponse.publicKey` JSON to DOM options. */
export function buildCreationOptions(
  publicKey: unknown,
): PublicKeyCredentialCreationOptions {
  if (!publicKey || typeof publicKey !== "object") {
    throw new PasskeyAuthError("challenge_malformed");
  }
  const source = publicKey as {
    rp?: { id?: unknown; name?: unknown };
    user?: { id?: unknown; name?: unknown; displayName?: unknown };
    challenge?: unknown;
    pubKeyCredParams?: unknown;
    timeout?: unknown;
    attestation?: unknown;
    authenticatorSelection?: unknown;
    excludeCredentials?: unknown;
    extensions?: unknown;
  };
  if (
    !source.rp ||
    typeof source.rp.id !== "string" ||
    !source.user ||
    typeof source.user.name !== "string" ||
    typeof source.user.displayName !== "string"
  ) {
    throw new PasskeyAuthError("challenge_malformed");
  }
  const options: PublicKeyCredentialCreationOptions = {
    rp: {
      id: source.rp.id,
      name: typeof source.rp.name === "string" ? source.rp.name : source.rp.id,
    },
    user: {
      id: decodeBase64Url(source.user.id),
      name: source.user.name,
      displayName: source.user.displayName,
    },
    challenge: decodeBase64Url(source.challenge),
    pubKeyCredParams: Array.isArray(source.pubKeyCredParams)
      ? (source.pubKeyCredParams as PublicKeyCredentialParameters[])
      : [],
    excludeCredentials: credentialDescriptors(source.excludeCredentials),
    attestation: "none",
  } as PublicKeyCredentialCreationOptions;
  if (typeof source.timeout === "number") options.timeout = source.timeout;
  if (typeof source.attestation === "string") {
    options.attestation = source.attestation as AttestationConveyancePreference;
  }
  if (source.authenticatorSelection && typeof source.authenticatorSelection === "object") {
    options.authenticatorSelection =
      source.authenticatorSelection as AuthenticatorSelectionCriteria;
  }
  // Request the WebAuthn PRF extension at registration so a later recovery
  // assertion can evaluate it (`prf: {}` enables it without evaluating). Any
  // server-provided extensions are preserved. An authenticator without PRF
  // support simply ignores the extension, so enrollment still succeeds; the
  // offline recovery code stays mandatory. The DOM typings for this build do
  // not declare `prf`, so the merged value is cast.
  const serverExtensions =
    source.extensions && typeof source.extensions === "object"
      ? (source.extensions as Record<string, unknown>)
      : {};
  const serverPrf = serverExtensions.prf;
  options.extensions = {
    ...serverExtensions,
    // Preserve any server-supplied PRF configuration (for example evaluation
    // salts) rather than clobbering it, while still enabling PRF when the server
    // did not request it (`prf: {}` enables without evaluating).
    prf:
      serverPrf && typeof serverPrf === "object" && !Array.isArray(serverPrf)
        ? serverPrf
        : {},
  } as unknown as AuthenticationExtensionsClientInputs;
  return options;
}

/** Serialize a created credential into the server's `RegisterPublicKeyCredential` JSON. */
export function serializeAttestation(
  credential: PublicKeyCredential,
): SerializedAttestation {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: encodeBase64Url(response.attestationObject),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
    },
  };
}

/** Serialize an asserted credential into the server's `PublicKeyCredential` JSON. */
export function serializeAssertion(
  credential: PublicKeyCredential,
): SerializedAssertion {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      authenticatorData: encodeBase64Url(response.authenticatorData),
      signature: encodeBase64Url(response.signature),
      userHandle: response.userHandle
        ? encodeBase64Url(response.userHandle)
        : null,
    },
  };
}

function webAuthnCredentials(
  options: PasskeyAuthOptions,
  method: "get" | "create",
): CredentialsContainer {
  const container = options.credentials ?? globalThis.navigator?.credentials;
  if (!container || typeof container[method] !== "function") {
    throw new PasskeyAuthError("webauthn_unsupported");
  }
  return container;
}

async function readChallenge(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetchImpl(url, init);
  } catch {
    throw new PasskeyAuthError("challenge_unavailable");
  }
  if (!response.ok) {
    throw new PasskeyAuthError("challenge_unavailable", response.status);
  }
  try {
    const body = (await response.json()) as { publicKey?: unknown };
    return body.publicKey ?? body;
  } catch {
    throw new PasskeyAuthError("challenge_malformed");
  }
}

/**
 * Complete a passkey authentication ceremony and install the server session.
 * Resolves on an authenticated session; throws a typed error otherwise.
 */
export async function authenticateWithPasskey(
  options: PasskeyAuthOptions = {},
): Promise<void> {
  const fetchImpl = options.fetchFn ?? fetch;
  const credentials = webAuthnCredentials(options, "get");
  const publicKey = await readChallenge(
    fetchImpl,
    options.challengeUrl ?? DEFAULT_CHALLENGE_URL,
    {
      method: "POST",
      credentials: "same-origin",
      redirect: "error",
      headers: { Accept: "application/json" },
    },
  );
  let assertion: Credential | null;
  try {
    assertion = await credentials.get({ publicKey: buildRequestOptions(publicKey) });
  } catch {
    throw new PasskeyAuthError("assertion_unavailable");
  }
  if (!assertion) {
    throw new PasskeyAuthError("assertion_unavailable");
  }
  let response: Response;
  try {
    response = await fetchImpl(options.verifyUrl ?? DEFAULT_VERIFY_URL, {
      method: "POST",
      credentials: "same-origin",
      redirect: "error",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(
        serializeAssertion(assertion as PublicKeyCredential),
      ),
    });
  } catch {
    throw new PasskeyAuthError("verification_rejected");
  }
  if (!response.ok) {
    throw new PasskeyAuthError("verification_rejected", response.status);
  }
}

/**
 * Enroll a new operator passkey (bootstrap path).
 *
 * `secret` is the operator bootstrap secret and is only ever sent to the
 * same-origin enrollment endpoint in the `x-evergreen-enroll-secret` header.
 */
export async function enrollPasskey(
  secret: string,
  options: PasskeyEnrollmentOptions = {},
): Promise<void> {
  if (!secret) {
    throw new PasskeyAuthError("enrollment_rejected");
  }
  const fetchImpl = options.fetchFn ?? fetch;
  const credentials = webAuthnCredentials(options, "create");
  const publicKey = await readChallenge(
    fetchImpl,
    options.registerChallengeUrl ?? DEFAULT_REGISTER_CHALLENGE_URL,
    {
      method: "POST",
      credentials: "same-origin",
      redirect: "error",
      headers: {
        Accept: "application/json",
        [ENROLLMENT_SECRET_HEADER]: secret,
      },
    },
  );
  let credential: Credential | null;
  try {
    credential = await credentials.create({
      publicKey: buildCreationOptions(publicKey),
    });
  } catch {
    throw new PasskeyAuthError("enrollment_rejected");
  }
  if (!credential) {
    throw new PasskeyAuthError("enrollment_rejected");
  }
  let response: Response;
  try {
    response = await fetchImpl(
      options.registerVerifyUrl ?? DEFAULT_REGISTER_VERIFY_URL,
      {
        method: "POST",
        credentials: "same-origin",
        redirect: "error",
        headers: {
          "Content-Type": "application/json",
          [ENROLLMENT_SECRET_HEADER]: secret,
        },
        body: JSON.stringify(
          serializeAttestation(credential as PublicKeyCredential),
        ),
      },
    );
  } catch {
    throw new PasskeyAuthError("enrollment_unavailable");
  }
  if (!response.ok) {
    throw new PasskeyAuthError(
      response.status >= 500 ? "enrollment_unavailable" : "enrollment_rejected",
      response.status,
    );
  }
}
