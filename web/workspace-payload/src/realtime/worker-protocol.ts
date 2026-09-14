import type { ConnectionStatus, WorkspaceErrorShape } from "../core/types";
import type { DecodedFrame, Priority, ResyncReason } from "./types";

export interface WorkerStartMessage {
  readonly type: "start";
  /** Same-origin websocket URL for `/v1/stream`. */
  readonly url: string;
  /** Origin used to validate the neutral path. */
  readonly baseUrl: string;
  readonly kid: string;
  /** Base64 raw 32-byte AES-256-GCM session key. Cleared from memory on stop. */
  readonly keyB64: string;
  readonly flushMs?: Record<Priority, number>;
  readonly capacity?: number;
}

export interface WorkerStopMessage {
  readonly type: "stop";
}

export type MainToWorker = WorkerStartMessage | WorkerStopMessage;

export interface WorkerReadyMessage {
  readonly type: "ready";
}
export interface WorkerStatusMessage {
  readonly type: "status";
  readonly status: ConnectionStatus;
}
export interface WorkerFramesMessage {
  readonly type: "frames";
  readonly frames: DecodedFrame[];
}
export interface WorkerResyncMessage {
  readonly type: "resync";
  readonly reason: ResyncReason;
  readonly fromSeq: number | null;
}
export interface WorkerErrorMessage {
  readonly type: "error";
  readonly error: WorkspaceErrorShape;
  readonly fatal: boolean;
}

export type WorkerToMain =
  | WorkerReadyMessage
  | WorkerStatusMessage
  | WorkerFramesMessage
  | WorkerResyncMessage
  | WorkerErrorMessage;
