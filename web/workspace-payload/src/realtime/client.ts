import { toWorkspaceErrorShape } from "../core/errors";
import { FRAME_FRESHNESS_TTL_MS, type ConnectionStatus, type WorkspaceErrorShape } from "../core/types";
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
  /**
   * Server-anchored wall clock (ms). When provided and a frame carries an
   * AEAD-authenticated `serverTimeMs`, a frame older than `maxFrameAgeMs` — or one
   * whose server time regressed — is refused and forces a resync, so an untrusted
   * relay cannot replay captured frames to keep the capital-committing circuit
   * breaker open. Optional: without it the client keeps the previous behaviour.
   */
  readonly serverNow?: () => number;
  /** Replay window for `serverTimeMs`; defaults to the frame-freshness TTL. */
  readonly maxFrameAgeMs?: number;
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
 * Bursts of malformed frames must not amplify `/v1/sync` traffic, but a single
 * lost resync request must not leave the stream degraded forever. Coalesce
 * within this window, then allow a later error to request recovery again.
 */
const RESYNC_COALESCE_MS = 3_000;

/**
 * How long the client may sit in a pre-live phase (socket open, no authenticated
 * snapshot) before it re-requests recovery. A relay can accept the upgrade and
 * then go silent, and the reconnect snapshot request is coalesced — without this
 * the only recovery request could be swallowed and the client would wedge until
 * a manual reload. The resync window still bounds the retry rate.
 */
const PRE_LIVE_RECOVERY_MS = 5_000;

/**
 * Maximum number of frames chained but not yet decrypted. Decryption is async,
 * so a compromised relay that floods frames faster than AEAD can process would
 * otherwise grow the chain (and retained ciphertext) without bound and OOM the
 * worker, which holds the only session key. Exceeding the backlog drops the
 * frame and forces a coalesced resync instead.
 */
const MAX_PENDING_INGEST = 256;

/**
 * Byte ceiling on the raw ciphertext chained but not yet decrypted. The frame
 * count alone bounds ~256 × the 2 MiB wire limit (~512 MiB of JS strings) in the
 * worker that holds the only key, so an attacker could still pressure memory.
 */
const MAX_PENDING_INGEST_BYTES = 8 * 1024 * 1024;

/**
 * Pure realtime orchestrator. The worker owns the socket and timers; this class
 * owns envelope validation, sequence decisions, decryption, decoding, batching
 * and the connection state machine — so it is fully testable without a browser.
 */
export class RealtimeClient {
  private readonly sequencer = new FrameSequencer();
  private readonly batcher: FrameBatcher;
  private readonly now: () => number;
  /**
   * Highest AEAD-authenticated `serverTimeMs` accepted in this session. Persists
   * across reconnects (only `start()` resets it) so a relay replaying an older
   * frame after a newer one is refused.
   */
  private maxServerTimeMs: number | null = null;
  private status: ConnectionStatus = INITIAL_STATUS;
  private started = false;
  private ingestChain: Promise<void> = Promise.resolve();
  /** Frames chained but not yet fully processed. */
  private pendingIngest = 0;
  /** Raw ciphertext bytes chained but not yet fully processed. */
  private pendingIngestBytes = 0;
  /** Bumped on every start so an in-flight decrypt cannot outlive a stop/restart. */
  private generation = 0;
  /**
   * True between a socket close and the next open. A frame that finishes
   * decrypting after the socket closed must not latch the phase back to `live`
   * (which would keep the capital-committing circuit breaker open on stale state
   * until the freshness watchdog fires).
   */
  private disconnected = false;
  /** Timestamp of the last resync request, for the bounded coalescing window. */
  private lastResyncAtMs = 0;
  /**
   * Highest applied sequence at the time recovery was last requested. A recovery
   * snapshot that carries no newer state (seq <= this) re-baselines without
   * proving the stream is current, so it must not refresh frame freshness or
   * re-arm the coalescing window — otherwise a replaying relay could keep the
   * capital-committing circuit breaker open and drive one `/v1/sync` per two
   * frames.
   */
  private resyncBaseline: number | null = null;
  /** True once a replayed pre-reconnect snapshot has been refused (avoid spam). */
  private refusedSnapshot = false;
  /**
   * Wall clock of the last authenticated frame (or of `start()`). Distinct from
   * `status.lastFrameAtMs`, which deliberately does not advance for a
   * non-progressing recovery snapshot. Used only to detect a pre-live wedge.
   */
  private lastActivityAtMs = 0;

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
    const wasLive = this.status.phase === "live";
    this.status = { ...this.status, ...patch };
    // A transition to `live` means recovery succeeded, so the next genuine gap or
    // reconnect may request recovery immediately. An accept-then-close relay never
    // reaches live, so its repeated requests stay inside the coalescing window and
    // cannot amplify `/v1/sync`.
    if (!wasLive && this.status.phase === "live") this.lastResyncAtMs = 0;
    this.options.onStatus(this.status);
  }

  start(): void {
    this.started = true;
    this.generation += 1;
    this.disconnected = false;
    this.sequencer.reset();
    this.lastResyncAtMs = 0;
    this.resyncBaseline = null;
    this.refusedSnapshot = false;
    this.maxServerTimeMs = null;
    this.lastActivityAtMs = this.now();
    this.setStatus({
      phase: "connecting",
      attempt: 0,
      nextRetryAtMs: null,
      reason: null,
    });
  }

  stop(): void {
    this.started = false;
    this.disconnected = true;
    this.setStatus({ phase: "offline", nextRetryAtMs: null, reason: null });
  }

  /** Socket open. We are not live until the first snapshot authenticates. */
  noteConnected(): void {
    if (!this.started) return;
    this.disconnected = false;
    // A reconnect always resyncs rather than resuming a possibly-stale baseline,
    // but it keeps the rollback high-water mark: an old snapshot replayed by an
    // untrusted relay must not be accepted as fresh state.
    this.sequencer.beginReconnect();
    // Do NOT reset the resync coalescing window here: a relay that accepts the
    // upgrade and immediately closes would otherwise re-arm `/v1/sync` on every
    // open (one request per connect). The bounded window governs across connects.
    this.refusedSnapshot = false;
    this.setStatus({
      phase: "connecting",
      nextRetryAtMs: null,
      reason: "Awaiting authenticated snapshot",
    });
  }

  /** Socket closed; caller schedules the reconnect. */
  noteDisconnected(reason: string, nextRetryAtMs: number | null = null): void {
    if (!this.started) return;
    this.disconnected = true;
    this.sequencer.beginResync();
    this.setStatus({
      phase: "reconnecting",
      attempt: this.status.attempt + 1,
      nextRetryAtMs,
      reason,
    });
  }

  /**
   * Public recovery request (used on socket open). Goes through the same
   * coalescing window as an internal gap/tamper resync, so an untrusted relay
   * cannot drive unbounded `/v1/sync` traffic by churning connections.
   */
  requestSnapshot(reason: ResyncReason = "reconnect"): void {
    this.requestResync(reason, this.sequencer.expectedSeq);
  }

  private requestResync(reason: ResyncReason, fromSeq: number | null): void {
    this.sequencer.beginResync();
    // Coalesce: an untrusted relay can emit malformed frames faster than the
    // backend can answer. The window is enforced from the last request — not
    // from a "pending" flag that a replayed stale snapshot could clear — so a
    // relay that alternates a stale snapshot with a malformed frame cannot
    // amplify `/v1/sync`; after the window a later error still asks again.
    const now = this.now();
    if (this.lastResyncAtMs !== 0 && now - this.lastResyncAtMs < RESYNC_COALESCE_MS) return;
    this.lastResyncAtMs = now;
    // Record the state we are asking the server to beat. Only a recovery frame
    // strictly newer than this counts as proven progress.
    this.resyncBaseline = this.sequencer.lastAppliedSeq;
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
    // Bound the backlog: the queue retains raw ciphertext across async decrypts,
    // by both frame count and total bytes.
    const bytes = rawText.length;
    if (
      this.pendingIngest >= MAX_PENDING_INGEST ||
      this.pendingIngestBytes + bytes > MAX_PENDING_INGEST_BYTES
    ) {
      this.options.onError(
        {
          code: "freshness",
          message: "Realtime ingest backlog exceeded the bounded queue.",
          retryable: true,
        },
        false,
      );
      this.requestResync("backpressure", this.sequencer.expectedSeq);
      return Promise.resolve();
    }
    this.pendingIngest += 1;
    this.pendingIngestBytes += bytes;
    // Capture the generation at enqueue time: a stop/restart that happens while
    // this frame sits in the queue must drop it, not let it run under the new
    // session's generation.
    const generation = this.generation;
    const run = this.ingestChain
      .then(() => this.ingestSerial(rawText, generation))
      .finally(() => {
        this.pendingIngest -= 1;
        this.pendingIngestBytes -= bytes;
      });
    this.ingestChain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async ingestSerial(rawText: string, generation: number): Promise<void> {
    if (!this.started || generation !== this.generation) return;

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
      case "await_snapshot":
        // While a resync is outstanding we must still authenticate and decode
        // frames: the recovery snapshot is the only frame that can clear the
        // baseline. Dropping it before decryption (the previous behaviour) left
        // the sequencer permanently `resyncing` after any gap/tamper/reconnect.
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
    // A stop() or restart() may have run while the async decrypt was in flight.
    // Never let a frame from the previous session reach the main thread.
    if (!this.started || generation !== this.generation) {
      plaintext.fill(0);
      return;
    }
    // The socket may have closed while this frame was decrypting. Accepting it
    // would latch the phase back to `live` on a dead socket and keep the
    // capital-committing circuit breaker open until the freshness watchdog fires.
    if (this.disconnected) {
      plaintext.fill(0);
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
    // Replay defence (BR-15): when the backend authenticates a per-frame server
    // clock, refuse a frame whose time regressed or is older than the freshness
    // window. An untrusted relay that withholds and later replays captured frames
    // would otherwise refresh `lastFrameAtMs` and keep `isConnectionFresh` (and
    // thus capital-committing mutations) open on stale state.
    if (frame.serverTimeMs !== null && this.options.serverNow) {
      const maxAge = this.options.maxFrameAgeMs ?? FRAME_FRESHNESS_TTL_MS;
      const nowServer = this.options.serverNow();
      const regressed =
        this.maxServerTimeMs !== null && frame.serverTimeMs < this.maxServerTimeMs;
      const tooOld = nowServer - frame.serverTimeMs > maxAge;
      if (regressed || tooOld) {
        this.options.onError(
          {
            code: "freshness",
            message: tooOld
              ? "Refused a replayed realtime frame older than the freshness window."
              : "Refused a realtime frame whose authenticated server time regressed.",
            retryable: true,
          },
          false,
        );
        // Drop the frame and force recovery; do NOT refresh frame freshness or
        // re-latch `live` on replayed state.
        this.requestResync("freshness", this.sequencer.expectedSeq);
        return;
      }
      this.maxServerTimeMs = frame.serverTimeMs;
    }
    // The relay proved it can deliver an authenticated frame; reset the pre-live
    // silence clock so the watchdog only fires on genuine stalls.
    this.lastActivityAtMs = this.now();

    const baseline = this.resyncBaseline;
    // A recovery frame is only "progress" when it carries state newer than what
    // was applied when recovery was requested. A snapshot exactly at the
    // high-water mark re-baselines (so recovery is never wedged) but proves
    // nothing new, so it must not refresh freshness or re-arm the window.
    const progressed = baseline === null || envelope.sequence > baseline;
    if (decision.kind === "await_snapshot") {
      // Only an authenticated snapshot can restore the baseline; a delta that
      // arrives while resyncing is dropped (it has no trustworthy base). A
      // strictly *older* snapshot is refused so state cannot roll backward —
      // including after a reconnect, where an untrusted relay could otherwise
      // replay a captured snapshot. A snapshot exactly at the high-water mark is
      // accepted: it re-baselines to the state already applied (no rollback) and
      // guarantees recovery when the server produced no newer frame while the
      // socket was down, instead of wedging the client permanently.
      if (frame.op !== "snapshot") {
        // The recovery snapshot was lost or suppressed (a failed/never-answered
        // `/v1/sync`, or an untrusted relay dropping it) while genuine deltas keep
        // arriving. Without this a client would wedge permanently: while
        // resyncing, `observe` reports no gap and every delta is dropped. Re-issue
        // a *coalesced* resync, so recovery is re-attempted at a bounded rate
        // instead of amplifying `/v1/sync`.
        this.requestResync("gap", this.sequencer.expectedSeq);
        return;
      }
      const applied = this.sequencer.lastAppliedSeq;
      if (applied !== null && envelope.sequence < applied) {
        if (!this.refusedSnapshot) {
          this.refusedSnapshot = true;
          this.options.onError(
            {
              code: "protocol",
              message: "Refused a recovery snapshot older than the applied state.",
              retryable: false,
              detail: `applied ${applied}, received ${envelope.sequence}`,
            },
            false,
          );
        }
        // Do NOT clear the coalescing window here: a relay that replays a stale
        // snapshot after every request could otherwise re-arm `/v1/sync`
        // indefinitely (one sync per two frames). The bounded window governs.
        return;
      }
      this.sequencer.onSnapshot(envelope.sequence);
      this.refusedSnapshot = false;
    } else if (frame.op === "snapshot") {
      this.sequencer.onSnapshot(envelope.sequence);
      this.refusedSnapshot = false;
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

    if (decision.kind === "accept" && frame.op !== "snapshot") {
      // Advance the rollback high-water mark only now that the frame has been
      // authenticated and decoded. Advancing it from the cleartext sequence in
      // `observe` let one injected/tampered envelope permanently refuse the
      // recovery snapshot (a DoS that survived reconnect).
      this.sequencer.noteApplied(envelope.sequence);
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

    const nonProgressingRecovery =
      decision.kind === "await_snapshot" && frame.op === "snapshot" && !progressed;
    this.setStatus({
      // An accepted recovery snapshot that does not beat the resync baseline is
      // delivered for rendering (read-only works) but the connection stays
      // degraded: the relay has not proven the stream is current, so
      // capital-committing mutations must fail closed and the window must not
      // reset.
      phase: nonProgressingRecovery ? "degraded" : "live",
      lastFrameAtMs: nonProgressingRecovery ? this.status.lastFrameAtMs : this.now(),
      reason: nonProgressingRecovery ? "Recovery snapshot carried no newer state." : null,
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

  /**
   * Health watchdog. A half-open socket (proxy black hole, stalled backend) stays
   * open and emits nothing, so the phase would otherwise latch `live` and the
   * circuit breaker would never halt trading on stale state. The worker calls
   * this on its timer.
   */
  watchdog(): void {
    if (!this.started) return;
    if (this.status.phase === "live") {
      const last = this.status.lastFrameAtMs;
      if (last === null || this.now() - last > FRAME_FRESHNESS_TTL_MS) {
        this.setStatus({
          phase: "degraded",
          reason: "No authenticated frame within the freshness window.",
        });
        // Ask for recovery rather than only flagging: a silent half-open stream
        // cannot self-heal without a resync request (coalesced by the window).
        this.requestResync("freshness", this.sequencer.expectedSeq);
      }
      return;
    }
    // Pre-live / degraded: a relay can accept the socket and then go silent (or
    // swallow the coalesced reconnect snapshot request). Without a retry the
    // workspace would sit in `connecting` forever with no path back to live. The
    // resync window still bounds the request rate, so this cannot amplify.
    if (
      (this.status.phase === "connecting" || this.status.phase === "degraded") &&
      this.now() - this.lastActivityAtMs > PRE_LIVE_RECOVERY_MS
    ) {
      this.requestResync("gap", this.sequencer.expectedSeq);
    }
  }
}
