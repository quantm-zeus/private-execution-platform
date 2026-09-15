import { utf8Decode } from "../core/base64";
import { workspaceError } from "../core/errors";
import type { DecodedFrame, FrameOp, Priority, RealtimeChannel } from "./types";

const OPS: readonly FrameOp[] = ["snapshot", "delta", "heartbeat", "mark", "error"];
const CHANNELS: readonly RealtimeChannel[] = [
  "ohlcv",
  "depth",
  "trades",
  "market",
  "orders",
  "execution",
  "alerts",
  "portfolio",
  "providers",
  "system",
];

/**
 * Default priority per channel. P0 execution-critical updates are immediate;
 * P1 visual updates batch ~50–100ms; P2 analytics ~250–1000ms; P3 metadata is
 * minute-scale. A frame may carry an explicit priority inside the ciphertext.
 */
const CHANNEL_PRIORITY: Record<RealtimeChannel, Priority> = {
  execution: 0,
  orders: 0,
  ohlcv: 1,
  depth: 1,
  trades: 1,
  market: 2,
  alerts: 2,
  portfolio: 2,
  providers: 3,
  system: 3,
};

export const MAX_ENTITY_KEY_LENGTH = 256;
export const MAX_PAYLOAD_BYTES = 512 * 1024;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPriority(value: unknown): value is Priority {
  return value === 0 || value === 1 || value === 2 || value === 3;
}

function isChannel(value: unknown): value is RealtimeChannel {
  return typeof value === "string" && (CHANNELS as readonly string[]).includes(value);
}

/**
 * Decode and normalize a decrypted inner frame. The payload stays `unknown` and
 * is validated again by each channel consumer; this function only guarantees the
 * envelope-level invariants every consumer relies on.
 */
export function decodeInnerFrame(bytes: Uint8Array, seq: number): DecodedFrame {
  if (bytes.length === 0 || bytes.length > MAX_PAYLOAD_BYTES) {
    throw workspaceError("protocol", "Decrypted frame payload size out of range.");
  }
  let text: string;
  try {
    text = utf8Decode(bytes);
  } catch {
    throw workspaceError("protocol", "Decrypted frame was not valid UTF-8.");
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw workspaceError("protocol", "Decrypted frame was not valid JSON.");
  }
  if (!isRecord(raw)) throw workspaceError("protocol", "Decrypted frame was not an object.");

  const op = raw.op;
  if (typeof op !== "string" || !(OPS as readonly string[]).includes(op)) {
    throw workspaceError("protocol", "Decrypted frame had an unknown operation.");
  }
  const channel = raw.channel;
  if (!isChannel(channel)) {
    throw workspaceError("protocol", "Decrypted frame had an unknown channel.");
  }
  const priority = isPriority(raw.priority) ? raw.priority : CHANNEL_PRIORITY[channel];

  const entityKeyRaw = raw.entity_key;
  const entityKey =
    typeof entityKeyRaw === "string" && entityKeyRaw.length > 0 && entityKeyRaw.length <= MAX_ENTITY_KEY_LENGTH
      ? entityKeyRaw
      : `${channel}:default`;

  const slot = raw.slot === null || raw.slot === undefined ? null : raw.slot;
  if (slot !== null && (typeof slot !== "number" || !Number.isSafeInteger(slot) || slot < 0)) {
    throw workspaceError("protocol", "Decrypted frame had an invalid slot.");
  }
  const sourceAgeRaw = raw.source_age_ms;
  const sourceAgeMs =
    typeof sourceAgeRaw === "number" && Number.isFinite(sourceAgeRaw) && sourceAgeRaw >= 0
      ? sourceAgeRaw
      : 0;
  // Optional AEAD-authenticated server wall clock. Absent/null is allowed (the
  // client then cannot detect delayed replay); a present non-finite/negative
  // value is a protocol error rather than a silent zero.
  const serverTimeRaw = raw.server_time_ms;
  let serverTimeMs: number | null;
  if (serverTimeRaw === null || serverTimeRaw === undefined) {
    serverTimeMs = null;
  } else if (
    typeof serverTimeRaw === "number" &&
    Number.isFinite(serverTimeRaw) &&
    serverTimeRaw >= 0
  ) {
    serverTimeMs = serverTimeRaw;
  } else {
    throw workspaceError("protocol", "Decrypted frame had an invalid server time.");
  }

  if ((op === "snapshot" || op === "delta") && raw.payload === undefined) {
    throw workspaceError("protocol", "Decrypted state frame carried no payload.");
  }

  return {
    seq,
    op: op as FrameOp,
    channel,
    priority,
    entityKey,
    slot,
    sourceAgeMs,
    serverTimeMs,
    payload: raw.payload,
  };
}
