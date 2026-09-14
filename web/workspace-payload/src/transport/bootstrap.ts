// Session bootstrap and capability discovery.
//
// The workspace never assumes a backend exists. It asks `/v1/bootstrap` for an
// authoritative capability set and fails closed (typed `unavailable`/`auth`
// errors) when the contract is missing or malformed. No default capability is
// ever enabled optimistically.

import { workspaceError } from "../core/errors";
import {
  CAPABILITY_KEYS,
  type CapabilityKey,
  type CapabilitySet,
  type ChainInfo,
  type KillSwitchState,
} from "../core/types";
import { assertNeutralUrl } from "./paths";

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
    });
  }
  return chains;
}

function parseKillSwitch(raw: unknown): KillSwitchState {
  if (!isRecord(raw)) return { enabled: true, reason: "Kill-switch state unavailable." };
  const enabled = raw.enabled === true;
  const reason = typeof raw.reason === "string" ? raw.reason : null;
  return { enabled, reason };
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

/**
 * Resolve the workspace session. Prefers an injected session (host handoff or
 * tests); otherwise performs the neutral `/v1/bootstrap` probe and fails closed.
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

  const url = assertNeutralUrl("/v1/bootstrap", baseUrl);
  let response: Response;
  try {
    response = await fetchFn(url.toString(), {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: "{}",
      signal: options.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw workspaceError("cancelled", "Bootstrap cancelled.", { retryable: true });
    }
    throw workspaceError("network", "Private API is unreachable.", { retryable: true });
  }

  if (!response.ok) mapBootstrapFailure(response.status);

  let raw: unknown;
  try {
    raw = await response.json();
  } catch {
    throw workspaceError("protocol", "Bootstrap response was not valid JSON.");
  }
  return parseWorkspaceSession(raw);
}
