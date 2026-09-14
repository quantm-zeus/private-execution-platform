import { toWorkspaceErrorShape } from "../core/errors";
import type { ConnectionStatus, WorkspaceErrorShape } from "../core/types";
import { FrameBatcher, DEFAULT_FLUSH_MS } from "./batcher";
import { decodeInnerFrame } from "./decoder";
import type { SessionDecryptor } from "./decryptor";
import { parseEnvelopeText } from "./envelope";
import { FrameSequencer } from "./sequencer";
import type { DecodedFrame, ResyncReason } from "./types";

export interface RealtimeClientOptions {
  readonly decryptor: SessionDecryptor;
  readonly expectedKid: string;
  readonly batcher?: FrameBatcher;
  readonly now?: () => number;
  readonly onFrames: (frames: DecodedFrame[]) => void;
  readonly onStatus: (status: ConnectionStatus) => void;
  readonly onResync: (reason: ResyncReason, fromSeq: number | null) => void;
  readonly onError: (error: WorkspaceErrorShape, fatal: boolean) => void;
}

const INITIAL_STATUS: ConnectionStatus = {
  phase: "idle",
  lastFrameAtMs: null,
  attempt: 0,
  nextRetryAtMs: null,
  reason: null,
};

/**
 * Pure realtime orchestrator. The worker owns the socket and timers; this class
 * owns envelope validation, sequence decisions, decryption, decoding, batching
 * and the connection state machine — so it is fully testable without a browser.
 */
export class RealtimeClient {
  private readonly sequencer = new FrameSequencer();
  private readonly batcher: FrameBatcher;
  private readonly now: () => number;
  private status: ConnectionStatus = INITIAL_STATUS;
  private started = false;
  private ingestChain: Promise<void> = Promise.resolve();

  constructor(private readonly options: RealtimeClientOptions) {
    this.now = options.now ?? (() => Date.now());
    this.batcher = options.batcher ?? new FrameBatcher({ capacity: 4_096, flushMs: DEFAULT_FLUSH_MS });
  }

  getStatus(): ConnectionStatus {
    return this.status;
  }

  get expectedSeq(): number | null {
    return this.sequencer.expectedSeq;
  }

  private setStatus(patch: Partial<ConnectionStatus>): void {
    this.status = { ...this.status, ...patch };
    this.options.onStatus(this.status);
  }

  start(): void {
    this.started = true;
    this.sequencer.reset();
    this.setStatus({
      phase: "connecting",
      attempt: 0,
      nextRetryAtMs: null,
      reason: null,
    });
  }

  stop(): void {
    this.started = false;
    this.setStatus({ phase: "offline", nextRetryAtMs: null, reason: null });
  }

  /** Socket open. We are not live until the first snapshot authenticates. */
  noteConnected(): void {
    if (!this.started) return;
    this.setStatus({
      phase: "connecting",
      nextRetryAtMs: null,
      reason: "Awaiting authenticated snapshot",
    });
  }

  /** Socket closed; caller schedules the reconnect. */
  noteDisconnected(reason: string, nextRetryAtMs: number | null = null): void {
    if (!this.started) return;
    this.sequencer.beginResync();
    this.setStatus({
      phase: "reconnecting",
      attempt: this.status.attempt + 1,
      nextRetryAtMs,
      reason,
    });
  }

  private requestResync(reason: ResyncReason, fromSeq: number | null): void {
    this.sequencer.beginResync();
    this.setStatus({ phase: "degraded", reason: `Resync requested (${reason})` });
    this.options.onResync(reason, fromSeq);
  }

  /**
   * Handle one cleartext envelope from the socket.
   *
   * Ingest is serialized: decryption is asynchronous, so two concurrent calls
   * could otherwise settle out of order and enqueue an older frame after a
   * newer one. Sequence decisions therefore happen in wire order.
   */
  ingest(rawText: string): Promise<void> {
    const next = this.ingestChain.then(() => this.ingestSerial(rawText));
    this.ingestChain = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  private async ingestSerial(rawText: string): Promise<void> {
    if (!this.started) return;

    let envelope;
    try {
      envelope = parseEnvelopeText(rawText);
    } catch (error) {
      this.options.onError(toWorkspaceErrorShape(error), false);
      this.requestResync("protocol", this.sequencer.expectedSeq);
      return;
    }

    if (envelope.kid !== this.options.expectedKid) {
      this.options.onError(
        { code: "auth", message: "Stream envelope key id mismatch.", retryable: false },
        false,
      );
      this.requestResync("tamper", this.sequencer.expectedSeq);
      return;
    }

    const unbased = this.sequencer.expectedSeq === null;
    const decision = this.sequencer.observe(envelope.sequence);
    switch (decision.kind) {
      case "duplicate":
        return;
      case "await_snapshot":
        return;
      case "gap":
        this.options.onError(
          {
            code: "freshness",
            message: "Realtime sequence gap detected.",
            retryable: true,
            detail: `expected ${decision.expected}, received ${decision.received}`,
          },
          false,
        );
        this.requestResync("gap", decision.expected);
        return;
      case "accept":
        break;
    }

    let plaintext: Uint8Array;
    try {
      plaintext = await this.options.decryptor.decrypt(envelope);
    } catch (error) {
      this.options.onError(toWorkspaceErrorShape(error), false);
      // Fail closed: never advance on an unauthenticated frame.
      this.requestResync("tamper", this.sequencer.expectedSeq);
      return;
    }

    let frame: DecodedFrame;
    try {
      frame = decodeInnerFrame(plaintext, envelope.sequence);
    } catch (error) {
      this.options.onError(toWorkspaceErrorShape(error), false);
      this.requestResync("protocol", this.sequencer.expectedSeq);
      return;
    } finally {
      plaintext.fill(0);
    }

    if (frame.op === "snapshot") {
      this.sequencer.onSnapshot(envelope.sequence);
    } else if (unbased) {
      this.options.onError(
        {
          code: "protocol",
          message: "Realtime stream did not begin with a snapshot.",
          retryable: false,
        },
        false,
      );
      this.requestResync("protocol", this.sequencer.expectedSeq);
      return;
    }

    const result = this.batcher.enqueue(frame);
    if (result.forcedResync) {
      this.options.onError(
        {
          code: "freshness",
          message: "Realtime backpressure exceeded the bounded buffer.",
          retryable: true,
        },
        false,
      );
      this.requestResync("backpressure", this.sequencer.expectedSeq);
    }

    this.setStatus({
      phase: this.status.phase === "degraded" && frame.op !== "snapshot" ? "degraded" : "live",
      lastFrameAtMs: this.now(),
      reason: null,
    });

    if (frame.priority === 0 || frame.op === "snapshot") {
      this.flushDue();
    }
  }

  /** Flush frames whose per-priority interval has elapsed. P0 is immediate. */
  flushDue(): void {
    const frames = this.batcher.drainDue(this.now());
    if (frames.length > 0) this.options.onFrames(frames);
  }

  /** Flush everything (used on stop/lock so the UI can settle). */
  flushAll(): void {
    const frames = this.batcher.drainAll();
    if (frames.length > 0) this.options.onFrames(frames);
  }
}
