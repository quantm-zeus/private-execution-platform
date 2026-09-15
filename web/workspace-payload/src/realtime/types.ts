import type { WorkspaceErrorShape } from "../core/types";

/**
 * Cleartext wire envelope. Per the PRD the only fields visible outside the AEAD
 * are generic `kid`/`nonce`/`sequence`/`ciphertext`; the operation type and all
 * trading semantics live inside `ciphertext`.
 */
export interface StreamEnvelope {
  readonly kid: string;
  readonly nonce: string;
  readonly sequence: number;
  readonly ciphertext: string;
}

export const PRIORITIES = [0, 1, 2, 3] as const;
export type Priority = (typeof PRIORITIES)[number];

export type FrameOp = "snapshot" | "delta" | "heartbeat" | "mark" | "error";

export type RealtimeChannel =
  | "ohlcv"
  | "depth"
  | "trades"
  | "market"
  | "orders"
  | "execution"
  | "alerts"
  | "portfolio"
  | "providers"
  | "system";

/** A decrypted, normalized, sequenced frame ready for the main thread. */
export interface DecodedFrame {
  readonly seq: number;
  readonly op: FrameOp;
  readonly channel: RealtimeChannel;
  readonly priority: Priority;
  /** Coalescing key: a newer frame with the same key replaces the older one. */
  readonly entityKey: string;
  readonly slot: number | null;
  readonly sourceAgeMs: number;
  /**
   * AEAD-authenticated server wall clock for this frame, when the backend
   * provides one (`server_time_ms`). The client uses it to refuse a replayed
   * frame that is older than the freshness window. `null` when absent.
   */
  readonly serverTimeMs: number | null;
  /** Channel-specific payload; validated by the consumer, never trusted blindly. */
  readonly payload: unknown;
}

export type ResyncReason =
  | "gap"
  | "tamper"
  | "protocol"
  | "reconnect"
  | "explicit"
  | "backpressure"
  | "freshness";

export interface RealtimeErrorEvent {
  readonly error: WorkspaceErrorShape;
  readonly fatal: boolean;
}
