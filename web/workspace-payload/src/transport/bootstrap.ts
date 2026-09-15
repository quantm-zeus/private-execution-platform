// Session bootstrap and capability discovery.
//
// The workspace never assumes a backend exists. It asks `/v1/bootstrap` for an
// authoritative capability set and fails closed (typed `unavailable`/`auth`
// errors) when the contract is missing or malformed. No default capability is
// ever enabled optimistically.
//
// BR-7: the request and response are opaque AEAD envelopes carried as
// `application/octet-stream` (UTF-8 JSON of the generic envelope). There is no
// cleartext operation type on the wire; without a BR-5 session key bootstrap
// fails closed rather than falling back to a cleartext JSON probe.

import { base64ToBytes, utf8Decode, utf8Encode } from "../core/base64";
import { workspaceError } from "../core/errors";
import { randomRequestId } from "../core/request-id";
import {
  CAPABILITY_KEYS,
  type CapabilityKey,
  type CapabilitySet,
  type ChainInfo,
  type KillSwitchState,
} from "../core/types";
import { WebCryptoDecryptor } from "../realtime/decryptor";
import { validateEnvelope } from "../realtime/envelope";
import { WebCryptoSealer } from "../realtime/sealer";
import type { HostSessionKey } from "../realtime/session-key";
import { assertNeutralUrl } from "./paths";
import { readBoundedJson } from "./http-body";

export interface WorkspaceSession {
  readonly protocolVersion: number;
  readonly capabilities: CapabilitySet;
  readonly tradingEnabled: boolean;
  readonly killSwitch: KillSwitchState;
  readonly chains: readonly ChainInfo[];
  readonly expiresAtMs: number;
  readonly keyId: string;
  readonly serverTimeMs: number;
}

export interface SessionBootstrapOptions {
  /** Base origin for neutral paths; defaults to the document origin. */
  readonly baseUrl?: string;
  readonly fetchFn?: typeof fetch;
  readonly signal?: AbortSignal;
  /** Test/host injection: an already-validated session. */
  readonly session?: WorkspaceSession;
  /**
   * BR-5 host key handoff. Bootstrap waits for this before sealing the request;
   * a `null`/missing key fails closed (never a cleartext fallback).
   */
  readonly hostKeyProvider?: () => Promise<HostSessionKey | null>;
  /** Explicit test/host key source (prefer `hostKeyProvider`). */
  readonly kid?: string;
  readonly c2sKeyB64?: string;
  readonly s2cKeyB64?: string;
  /**
   * Monotonic per-`kid` bootstrap sequence. The server keeps a replay window for
   * the lifetime of the key, so a retry/reload must not reuse sequence 0; the
   * store supplies a strictly increasing value. Defaults to 0 for a fresh key.
   */
  readonly sequence?: number;
}

function allCapabilitiesFalse(): CapabilitySet {
  const out = {} as Record<CapabilityKey, boolean>;
  for (const key of CAPABILITY_KEYS) out[key] = false;
  return out;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseCapabilities(raw: unknown): CapabilitySet {
  if (!isRecord(raw)) throw workspaceError("protocol", "Malformed capability set.");
  const out = allCapabilitiesFalse() as Record<CapabilityKey, boolean>;
  for (const key of CAPABILITY_KEYS) {
    const value = raw[key];
    out[key] = value === true;
  }
  return out;
}

function parseChains(raw: unknown): readonly ChainInfo[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) throw workspaceError("protocol", "Malformed chain list.");
  // Bound the list before iterating: an unbounded array is a cheap relay-side OOM.
  if (raw.length > 256) throw workspaceError("protocol", "Chain list exceeded the size limit.");
  const chains: ChainInfo[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) throw workspaceError("protocol", "Malformed chain entry.");
    if (typeof entry.id !== "string" || entry.id.length === 0 || entry.id.length > 64) {
      throw workspaceError("protocol", "Malformed chain id.");
    }
    chains.push({
      id: entry.id,
      display: typeof entry.display === "string" ? entry.display : entry.id,
      enabled: entry.enabled === true,
      // BR-11: optional canonical quote/native asset for the chain. A missing or
      // non-string value stays `null` so consumers fail closed rather than
      // fabricating a counterparty token.
      nativeToken:
        typeof entry.native_token === "string" && entry.native_token.length > 0
          ? entry.native_token
          : null,
    });
  }
  return chains;
}

function parseKillSwitch(raw: unknown): KillSwitchState {
  if (!isRecord(raw)) return { enabled: true, reason: "Kill-switch state unavailable." };
  // Fail closed on a malformed-but-object block: a stripped/renamed `enabled`
  // field must not silently disengage the safety control. Only an explicit
  // boolean may clear the halt.
  if (typeof raw.enabled !== "boolean") {
    return { enabled: true, reason: "Kill-switch state unavailable." };
  }
  const reason = typeof raw.reason === "string" ? raw.reason : null;
  return { enabled: raw.enabled, reason };
}

/** Strictly validate an untrusted bootstrap payload. Fails closed on any gap. */
export function parseWorkspaceSession(raw: unknown): WorkspaceSession {
  if (!isRecord(raw)) throw workspaceError("protocol", "Malformed bootstrap response.");
  if (raw.protocol_version !== 1) {
    throw workspaceError("protocol", "Unsupported workspace protocol version.");
  }
  const sessionRaw = raw.session;
  if (!isRecord(sessionRaw)) throw workspaceError("protocol", "Malformed session block.");
  const keyId = sessionRaw.key_id;
  const expiresAtMs = sessionRaw.expires_at_ms;
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw workspaceError("protocol", "Missing session key id.");
  }
  if (typeof expiresAtMs !== "number" || !Number.isFinite(expiresAtMs)) {
    throw workspaceError("protocol", "Missing session expiry.");
  }
  const serverTimeMs = raw.server_time_ms;
  if (typeof serverTimeMs !== "number" || !Number.isFinite(serverTimeMs)) {
    throw workspaceError("protocol", "Missing server time anchor.");
  }
  return {
    protocolVersion: 1,
    capabilities: parseCapabilities(raw.capabilities),
    tradingEnabled: raw.trading_enabled === true,
    killSwitch: parseKillSwitch(raw.kill_switch),
    chains: parseChains(raw.chains),
    expiresAtMs,
    keyId,
    serverTimeMs,
  };
}

function mapBootstrapFailure(status: number): never {
  if (status === 401 || status === 403) {
    throw workspaceError("auth", "Workspace session is not authorized.", { retryable: false });
  }
  if (status === 404 || status === 405 || status === 501) {
    throw workspaceError(
      "capability_missing",
      "Private API is not available on this deployment.",
      { retryable: false, detail: `bootstrap ${status}` },
    );
  }
  throw workspaceError("server", "Workspace bootstrap failed.", {
    retryable: status >= 500,
    detail: `bootstrap ${status}`,
  });
}

interface BootstrapKeys {
  readonly kid: string;
  readonly c2sKeyB64: string;
  readonly s2cKeyB64: string;
}

/**
 * Resolve the BR-5 directional keys bootstrap needs. Both directions are
 * required: c2s seals the request and s2c opens the response. Without a key
 * source bootstrap cannot speak the opaque contract and must fail closed.
 */
async function resolveBootstrapKeys(
  options: SessionBootstrapOptions,
): Promise<BootstrapKeys> {
  if (options.hostKeyProvider) {
    const key = await options.hostKeyProvider();
    if (!key || !key.c2sKeyB64) {
      throw workspaceError(
        "capability_missing",
        "Private API session key is unavailable (BR-5).",
        { retryable: false, detail: "bootstrap key handoff missing" },
      );
    }
    return { kid: key.kid, c2sKeyB64: key.c2sKeyB64, s2cKeyB64: key.s2cKeyB64 };
  }
  if (options.kid && options.c2sKeyB64 && options.s2cKeyB64) {
    return { kid: options.kid, c2sKeyB64: options.c2sKeyB64, s2cKeyB64: options.s2cKeyB64 };
  }
  throw workspaceError("capability_missing", "Private API session key is unavailable (BR-5).", {
    retryable: false,
    detail: "bootstrap key handoff missing",
  });
}

async function importBootstrapCrypto(
  keys: BootstrapKeys,
): Promise<{ sealer: WebCryptoSealer; decryptor: WebCryptoDecryptor }> {
  const c2sRaw = base64ToBytes(keys.c2sKeyB64);
  const s2cRaw = base64ToBytes(keys.s2cKeyB64);
  try {
    const sealer = await WebCryptoSealer.fromRawKey(c2sRaw);
    const decryptor = await WebCryptoDecryptor.fromRawKey(s2cRaw, keys.kid);
    return { sealer, decryptor };
  } finally {
    // Zeroize the raw key byte arrays now that they are imported as
    // non-extractable CryptoKeys (the import helpers zeroize their own copy).
    c2sRaw.fill(0);
    s2cRaw.fill(0);
  }
}

/**
 * Resolve the workspace session. Prefers an injected session (host handoff or
 * tests); otherwise performs the neutral opaque `/v1/bootstrap` probe and fails
 * closed.
 */
export async function bootstrapWorkspaceSession(
  options: SessionBootstrapOptions = {},
): Promise<WorkspaceSession> {
  if (options.session) return options.session;

  const baseUrl =
    options.baseUrl ?? (typeof location !== "undefined" ? location.origin : undefined);
  if (!baseUrl) {
    throw workspaceError("capability_missing", "Private API origin is unavailable in this runtime.");
  }
  const fetchFn = options.fetchFn ?? (typeof fetch !== "undefined" ? fetch : undefined);
  if (!fetchFn) {
    throw workspaceError("capability_missing", "Private API is not reachable from this runtime.");
  }

  const keys = await resolveBootstrapKeys(options);
  const { sealer, decryptor } = await importBootstrapCrypto(keys);

  // Bootstrap owns its own sequence window (per-purpose server replay windows).
  // The server never resets that window for the life of the `kid`, so a
  // retry/reload must advance the sequence; reusing 0 would be rejected as a
  // replay and wedge the workspace until a manual re-unlock.
  const sequence = options.sequence ?? 0;
  const requestId = randomRequestId();
  const plaintext = utf8Encode(
    JSON.stringify({ op: "bootstrap", protocol_version: 1, request_id: requestId }),
  );
  let sealed;
  try {
    sealed = await sealer.seal({ kid: keys.kid, sequence }, plaintext);
  } finally {
    plaintext.fill(0);
  }
  const envelopeBody = utf8Encode(
    JSON.stringify({
      kid: keys.kid,
      sequence,
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext,
    }),
  );

  const url = assertNeutralUrl("/v1/bootstrap", baseUrl);
  let response: Response;
  try {
    response = await fetchFn(url.toString(), {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/octet-stream" },
      body: envelopeBody,
      signal: options.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw workspaceError("cancelled", "Bootstrap cancelled.", { retryable: true });
    }
    throw workspaceError("network", "Private API is unreachable.", { retryable: true });
  }

  if (!response.ok) mapBootstrapFailure(response.status);

  // The response is bounded before parsing: a compromised relay must not be able
  // to OOM the main thread with a multi-gigabyte body (the command path already
  // enforces the same ceiling). The response is the bare envelope (a wrapped
  // `{envelope}` shape is still accepted for compatibility).
  const raw = await readBoundedJson(response);
  if (!raw || typeof raw !== "object") {
    throw workspaceError("protocol", "Malformed bootstrap response.");
  }
  const envelope = validateEnvelope((raw as Record<string, unknown>).envelope ?? raw);
  if (envelope.sequence !== sequence) {
    throw workspaceError("protocol", "Bootstrap response sequence mismatch.", {
      retryable: false,
      detail: `expected ${sequence}, received ${envelope.sequence}`,
    });
  }
  const decrypted = await decryptor.decrypt(envelope);
  try {
    let body: unknown;
    try {
      body = JSON.parse(utf8Decode(decrypted));
    } catch {
      throw workspaceError("protocol", "Bootstrap response was not valid JSON.");
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw workspaceError("protocol", "Bootstrap response was malformed.");
    }
    if ((body as Record<string, unknown>).request_id !== requestId) {
      throw workspaceError("protocol", "Bootstrap response was not bound to this request.", {
        retryable: false,
        detail: "request binding",
      });
    }
    return parseWorkspaceSession(body);
  } finally {
    decrypted.fill(0);
  }
}
