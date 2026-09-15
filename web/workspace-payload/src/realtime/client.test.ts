import { describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64, utf8Encode } from "../core/base64";
import { FRAME_FRESHNESS_TTL_MS, type ConnectionStatus, type WorkspaceErrorShape } from "../core/types";
import { FrameBatcher } from "./batcher";
import { RealtimeClient } from "./client";
import type { SessionDecryptor } from "./decryptor";
import type { StreamEnvelope, DecodedFrame, ResyncReason } from "./types";

const KID = "kid-1";
const zeroFlush = { 0: 0, 1: 0, 2: 0, 3: 0 } as const;

function envelope(sequence: number, inner: unknown, kid = KID): string {
  return JSON.stringify({
    kid,
    nonce: bytesToBase64(new Uint8Array(12)),
    sequence,
    ciphertext: bytesToBase64(utf8Encode(JSON.stringify(inner))),
  } satisfies StreamEnvelope);
}

class FakeDecryptor implements SessionDecryptor {
  fail = false;
  delayFor: (sequence: number) => number = () => 0;
  async decrypt(envelopeValue: StreamEnvelope): Promise<Uint8Array> {
    const delay = this.delayFor(envelopeValue.sequence);
    if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
    if (this.fail) throw new Error("AEAD authentication failed");
    return base64ToBytes(envelopeValue.ciphertext);
  }
}

interface Harness {
  client: RealtimeClient;
  decryptor: FakeDecryptor;
  frames: DecodedFrame[];
  statuses: ConnectionStatus[];
  resyncs: { reason: ResyncReason; fromSeq: number | null }[];
  errors: WorkspaceErrorShape[];
}

function harness(
  capacity = 64,
  now: () => number = () => 1_000,
  serverNow?: () => number,
): Harness {
  const decryptor = new FakeDecryptor();
  const frames: DecodedFrame[] = [];
  const statuses: ConnectionStatus[] = [];
  const resyncs: { reason: ResyncReason; fromSeq: number | null }[] = [];
  const errors: WorkspaceErrorShape[] = [];
  const client = new RealtimeClient({
    decryptor,
    expectedKid: KID,
    now,
    serverNow,
    batcher: new FrameBatcher({ capacity, flushMs: zeroFlush }),
    onFrames: (batch) => frames.push(...batch),
    onStatus: (status) => statuses.push(status),
    onResync: (reason, fromSeq) => resyncs.push({ reason, fromSeq }),
    onError: (error) => errors.push(error),
  });
  return { client, decryptor, frames, statuses, resyncs, errors };
}

// `value` is the decoded inner payload, not necessarily a number: the byte-bound
// regression test injects a large opaque blob to exercise the wire-size ceiling.
const snapshot = (value: unknown) => ({ op: "snapshot", channel: "ohlcv", entity_key: "ohlcv:base", payload: { value } });
const delta = (value: unknown, entityKey = "ohlcv:base") => ({
  op: "delta",
  channel: "ohlcv",
  entity_key: entityKey,
  payload: { value },
});

describe("RealtimeClient", () => {
  it("accepts a snapshot then contiguous deltas and reports live", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    await h.client.ingest(envelope(1, delta(2)));
    h.client.flushDue();
    expect(h.client.getStatus().phase).toBe("live");
    expect(h.frames.map((f) => f.seq)).toEqual([0, 1]);
    expect(h.resyncs).toHaveLength(0);
  });

  it("keeps requesting recovery when the socket opens but stays silent (pre-live)", () => {
    let now = 1_000;
    const h = harness(64, () => now);
    h.client.start();
    // Socket open, but the relay never sends an authenticated snapshot. The
    // reconnect `requestSnapshot` may have been swallowed by the coalescing
    // window, so the watchdog must re-request recovery instead of wedging.
    h.client.noteConnected();
    expect(h.resyncs).toHaveLength(0);
    now += 5_001;
    h.client.watchdog();
    expect(h.resyncs.length).toBe(1);
    expect(h.resyncs[0]?.reason).toBe("gap");
    // Bounded by the resync coalescing window: a relay cannot amplify /v1/sync.
    h.client.watchdog();
    h.client.watchdog();
    expect(h.resyncs).toHaveLength(1);
    now += 3_001;
    h.client.watchdog();
    expect(h.resyncs).toHaveLength(2);
  });

  it("drops duplicate and replayed sequences", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    await h.client.ingest(envelope(0, snapshot(1)));
    await h.client.ingest(envelope(1, delta(2)));
    await h.client.ingest(envelope(1, delta(2)));
    h.client.flushDue();
    expect(h.frames.map((f) => f.seq)).toEqual([0, 1]);
  });

  it("forces a snapshot resync on a sequence gap and delivers nothing", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    h.frames.length = 0;
    await h.client.ingest(envelope(5, delta(9)));
    expect(h.frames).toHaveLength(0);
    expect(h.resyncs.at(-1)).toEqual({ reason: "gap", fromSeq: 1 });
    expect(h.client.getStatus().phase).toBe("degraded");
  });

  it("fails closed on AEAD tamper and never delivers the frame", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    h.frames.length = 0;
    h.decryptor.fail = true;
    await h.client.ingest(envelope(1, delta(2)));
    expect(h.frames).toHaveLength(0);
    expect(h.resyncs.at(-1)?.reason).toBe("tamper");
    expect(h.errors.at(-1)?.code).toBe("unknown");
  });

  it("rejects an envelope with an unexpected key id before decrypting", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1), "other-kid"));
    expect(h.frames).toHaveLength(0);
    expect(h.resyncs.at(-1)?.reason).toBe("tamper");
  });

  it("rejects a malformed cleartext envelope without crashing", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest("{not json");
    expect(h.frames).toHaveLength(0);
    expect(h.resyncs.at(-1)?.reason).toBe("protocol");
    expect(h.errors).toHaveLength(1);
  });

  it("ignores frames before start()", async () => {
    const h = harness();
    await h.client.ingest(envelope(0, snapshot(1)));
    expect(h.frames).toHaveLength(0);
    expect(h.statuses).toHaveLength(0);
  });

  it("bounds the buffer under visual overflow and forces a resync for the dropped state", async () => {
    const h = harness(1);
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    h.frames.length = 0;
    await h.client.ingest(envelope(1, delta(2, "ohlcv:a")));
    await h.client.ingest(envelope(2, delta(3, "ohlcv:b")));
    h.client.flushDue();
    expect(h.frames).toHaveLength(1);
    expect(h.frames[0]!.entityKey).toBe("ohlcv:b");
    expect(h.resyncs.at(-1)?.reason).toBe("backpressure");
  });

  it("rejects a stream that does not begin with a snapshot", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, delta(1)));
    expect(h.frames).toHaveLength(0);
    expect(h.resyncs.at(-1)?.reason).toBe("protocol");
  });

  it("serializes concurrent ingests so frames never deliver out of order", async () => {
    const h = harness();
    h.decryptor.delayFor = (sequence) => (sequence === 1 ? 40 : 0);
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    h.frames.length = 0;
    const first = h.client.ingest(envelope(1, delta(2, "ohlcv:a")));
    const second = h.client.ingest(envelope(2, delta(3, "ohlcv:b")));
    await Promise.all([first, second]);
    h.client.flushDue();
    expect(h.frames.map((frame) => frame.seq)).toEqual([1, 2]);
  });

  it("transitions to reconnecting with an incremented attempt on disconnect", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.noteDisconnected("socket closed", 12_345);
    const status = h.client.getStatus();
    expect(status.phase).toBe("reconnecting");
    expect(status.attempt).toBe(1);
    expect(status.nextRetryAtMs).toBe(12_345);
  });

  it("recovers to live by accepting the snapshot after a gap", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    h.frames.length = 0;
    await h.client.ingest(envelope(5, delta(9)));
    expect(h.resyncs.at(-1)?.reason).toBe("gap");
    // The recovery snapshot must clear the resync baseline, not be dropped.
    await h.client.ingest(envelope(6, snapshot(10)));
    h.client.flushDue();
    expect(h.frames.map((f) => f.seq)).toEqual([6]);
    expect(h.client.expectedSeq).toBe(7);
    expect(h.client.getStatus().phase).toBe("live");
    await h.client.ingest(envelope(7, delta(11)));
    h.client.flushDue();
    expect(h.frames.map((f) => f.seq)).toEqual([6, 7]);
  });

  it("drops deltas but accepts the authenticated snapshot while awaiting a resync", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    h.frames.length = 0;
    await h.client.ingest(envelope(5, delta(9)));
    // A delta arriving before the recovery snapshot must not be applied.
    await h.client.ingest(envelope(1, delta(2)));
    h.client.flushDue();
    expect(h.frames).toHaveLength(0);
    await h.client.ingest(envelope(2, snapshot(3)));
    h.client.flushDue();
    expect(h.frames.map((f) => f.seq)).toEqual([2]);
  });

  it("recovers after an AEAD tamper when a fresh authenticated snapshot arrives", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    h.frames.length = 0;
    h.decryptor.fail = true;
    await h.client.ingest(envelope(1, delta(2)));
    expect(h.resyncs.at(-1)?.reason).toBe("tamper");
    h.decryptor.fail = false;
    await h.client.ingest(envelope(2, snapshot(3)));
    h.client.flushDue();
    expect(h.frames.map((f) => f.seq)).toEqual([2]);
    expect(h.client.getStatus().phase).toBe("live");
  });

  it("refuses a replayed older snapshot while resyncing (no state rollback)", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    await h.client.ingest(envelope(1, delta(2)));
    h.client.flushDue();
    h.frames.length = 0;
    // Force a resync, then replay a snapshot older than the applied state.
    await h.client.ingest(envelope(5, delta(9)));
    expect(h.resyncs.at(-1)?.reason).toBe("gap");
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    expect(h.frames).toHaveLength(0);
    expect(h.client.expectedSeq).toBe(2);
    // A genuinely newer snapshot still recovers.
    await h.client.ingest(envelope(6, snapshot(3)));
    h.client.flushDue();
    expect(h.frames.map((f) => f.seq)).toEqual([6]);
  });

  it("keeps the rollback high-water mark across reconnect and refuses an older replayed snapshot", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    await h.client.ingest(envelope(1, delta(2)));
    h.client.flushDue();
    h.frames.length = 0;
    h.client.noteConnected();
    // The last applied sequence is preserved across reconnect, so an untrusted
    // relay replaying a captured older snapshot cannot be accepted.
    expect(h.client.expectedSeq).toBe(2);
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    expect(h.frames).toHaveLength(0);
    expect(h.errors.some((error) => error.code === "protocol")).toBe(true);
    // A bare delta while awaiting the recovery snapshot is dropped.
    await h.client.ingest(envelope(9, delta(4)));
    h.client.flushDue();
    expect(h.frames).toHaveLength(0);
    // A snapshot exactly at the high-water mark is not a rollback: it
    // re-baselines (a strict `<=` rule wedged the client forever) and lets
    // contiguous deltas resume. But it carries no new state, so the feed stays
    // degraded until a newer frame arrives — it must not be able to re-arm the
    // window or refresh freshness.
    await h.client.ingest(envelope(1, snapshot(5)));
    h.client.flushDue();
    expect(h.frames.map((f) => f.seq)).toEqual([1]);
    expect(h.client.expectedSeq).toBe(2);
    expect(h.client.getStatus().phase).toBe("degraded");
    // Contiguous deltas from the re-baselined sequence are accepted and recover.
    await h.client.ingest(envelope(2, delta(6)));
    h.client.flushDue();
    expect(h.frames.map((f) => f.seq)).toEqual([1, 2]);
    expect(h.client.expectedSeq).toBe(3);
    expect(h.client.getStatus().phase).toBe("live");
  });

  it("bounds resync requests when a relay interleaves stale snapshots with malformed frames", async () => {
    let now = 1_000;
    const h = harness(64, () => now);
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    await h.client.ingest(envelope(1, delta(2)));
    h.client.flushDue();
    h.frames.length = 0;
    // Gap forces the first resync.
    await h.client.ingest(envelope(5, delta(9)));
    const afterGap = h.resyncs.length;
    expect(afterGap).toBe(1);

    // A relay that captured a genuine older snapshot alternates it with a
    // malformed frame. The refusal must NOT re-arm the coalescing window, or
    // each pair would trigger another `/v1/sync` (amplification).
    for (let i = 0; i < 6; i++) {
      h.decryptor.fail = false;
      await h.client.ingest(envelope(0, snapshot(1))); // refused (rollback)
      h.decryptor.fail = true;
      await h.client.ingest(envelope(2 + i, delta(3 + i))); // tamper
    }
    expect(h.resyncs.length).toBe(afterGap);

    // After the bounded window a later error still requests recovery: no wedge.
    now += 4_000;
    await h.client.ingest(envelope(9, delta(9)));
    expect(h.resyncs.length).toBe(afterGap + 1);
    expect(h.resyncs.at(-1)?.reason).toBe("tamper");
  });

  it("does not advance the rollback mark from an unauthenticated frame", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    await h.client.ingest(envelope(1, delta(2)));
    h.client.flushDue();
    h.frames.length = 0;
    // The untrusted edge injects a cleartext envelope at the expected sequence
    // whose AEAD authentication fails. It must not advance the high-water mark,
    // or the genuine recovery snapshot would be refused forever.
    h.decryptor.fail = true;
    await h.client.ingest(envelope(2, delta(3)));
    expect(h.resyncs.at(-1)?.reason).toBe("tamper");
    h.decryptor.fail = false;
    // The server was idle, so its recovery snapshot is at the last applied
    // sequence (1). With the mark correctly still at 1 this recovers; if the
    // tampered frame had advanced it to 2 the client would stay wedged.
    await h.client.ingest(envelope(1, snapshot(4)));
    h.client.flushDue();
    expect(h.frames.map((f) => f.seq)).toEqual([1]);
    // No newer state: re-baselined for rendering, but not fresh/live.
    expect(h.client.getStatus().phase).toBe("degraded");
    await h.client.ingest(envelope(2, delta(4)));
    h.client.flushDue();
    expect(h.client.getStatus().phase).toBe("live");
  });

  it("does not re-arm the window or refresh freshness on a replayed equal snapshot", async () => {
    let now = 1_000;
    const h = harness(64, () => now);
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    await h.client.ingest(envelope(1, delta(2)));
    h.client.flushDue();
    const freshnessAtGap = h.client.getStatus().lastFrameAtMs;

    // Gap forces the first (and only in-window) resync.
    await h.client.ingest(envelope(5, delta(9)));
    expect(h.resyncs).toHaveLength(1);

    // Relay replays the genuine snapshot at the high-water mark: accepted for
    // rendering, but it must not refresh the freshness clock...
    await h.client.ingest(envelope(1, snapshot(5)));
    expect(h.client.getStatus().phase).toBe("degraded");
    expect(h.client.getStatus().lastFrameAtMs).toBe(freshnessAtGap);

    // ...nor re-arm the coalescing window, so an immediate second gap cannot
    // drive another `/v1/sync` (the amplifier this guards against).
    await h.client.ingest(envelope(9, delta(9)));
    expect(h.resyncs).toHaveLength(1);
  });

  it("re-requests recovery after the bounded coalescing window (no permanent wedge)", async () => {
    const decryptor = new FakeDecryptor();
    const resyncs: ResyncReason[] = [];
    let now = 1_000;
    const client = new RealtimeClient({
      decryptor,
      expectedKid: KID,
      now: () => now,
      batcher: new FrameBatcher({ capacity: 8, flushMs: zeroFlush }),
      onFrames: () => {},
      onStatus: () => {},
      onResync: (reason) => resyncs.push(reason),
      onError: () => {},
    });
    client.start();
    await client.ingest(envelope(0, snapshot(1)));
    await client.ingest(envelope(1, delta(2)));

    decryptor.fail = true;
    await client.ingest(envelope(2, delta(3)));
    expect(resyncs).toEqual(["tamper"]);

    // A second error inside the window is coalesced (no /v1/sync amplification).
    await client.ingest(envelope(3, delta(4)));
    expect(resyncs).toEqual(["tamper"]);

    // After the window a later error must be able to request recovery again, so
    // a lost sync request cannot leave the stream degraded forever.
    now += 4_000;
    await client.ingest(envelope(4, delta(5)));
    expect(resyncs).toEqual(["tamper", "tamper"]);
  });

  it("re-requests recovery when a suppressed snapshot leaves only genuine deltas", async () => {
    const decryptor = new FakeDecryptor();
    const resyncs: ResyncReason[] = [];
    let now = 1_000;
    const client = new RealtimeClient({
      decryptor,
      expectedKid: KID,
      now: () => now,
      batcher: new FrameBatcher({ capacity: 8, flushMs: zeroFlush }),
      onFrames: () => {},
      onStatus: () => {},
      onResync: (reason) => resyncs.push(reason),
      onError: () => {},
    });
    client.start();
    await client.ingest(envelope(0, snapshot(1)));
    await client.ingest(envelope(1, delta(2)));

    // A gap requests recovery, but the untrusted relay suppresses the snapshot
    // and keeps relaying perfectly authentic deltas.
    await client.ingest(envelope(5, delta(9)));
    expect(resyncs).toEqual(["gap"]);
    await client.ingest(envelope(6, delta(10)));
    expect(resyncs).toEqual(["gap"]); // coalesced inside the window

    // After the window, another authentic delta must re-request recovery rather
    // than leaving the stream degraded forever.
    now += 4_000;
    await client.ingest(envelope(7, delta(11)));
    expect(resyncs).toEqual(["gap", "gap"]);
    expect(client.getStatus().phase).toBe("degraded");
  });

  it("bounds the pending ingest queue under a frame flood", async () => {
    const h = harness();
    h.client.start();
    h.decryptor.delayFor = () => 1;
    const pending: Promise<void>[] = [];
    for (let i = 0; i < 300; i += 1) pending.push(h.client.ingest(envelope(i, delta(i + 1))));
    await Promise.all(pending);
    expect(h.resyncs.some((r) => r.reason === "backpressure")).toBe(true);
  });

  it("bounds the pending ingest queue by total bytes, not only frame count", async () => {
    const h = harness();
    h.client.start();
    h.decryptor.delayFor = () => 1;
    // Four ~4 MiB wire frames exceed the 8 MiB byte ceiling long before the
    // 256-frame count ceiling, so a few oversized frames cannot pressure memory.
    const big = (seq: number) => envelope(seq, delta({ blob: "x".repeat(3 * 1024 * 1024) }));
    const pending = [0, 1, 2, 3].map((seq) => h.client.ingest(big(seq)));
    await Promise.all(pending);
    expect(h.resyncs.some((r) => r.reason === "backpressure")).toBe(true);
    // Serializing/decrypting ~4 MiB frames can exceed the default 5s budget under
    // a loaded parallel test run; give this byte-bound test an explicit budget.
  }, 20_000);

  it("drops an in-flight frame if the client is stopped before it decrypts", async () => {
    const h = harness();
    h.client.start();
    h.decryptor.delayFor = () => 20;
    const pending = h.client.ingest(envelope(0, snapshot(1)));
    h.client.stop();
    await pending;
    h.client.flushAll();
    expect(h.frames).toHaveLength(0);
  });

  it("drops a queued frame when the client is stopped and restarted before it runs", async () => {
    const h = harness();
    h.client.start();
    h.decryptor.delayFor = () => 20;
    // Enqueued under generation 1; stop/start bumps the generation before the
    // queued task runs, so it must not execute under the new session.
    const pending = h.client.ingest(envelope(0, snapshot(1)));
    h.client.stop();
    h.client.start();
    await pending;
    h.client.flushAll();
    expect(h.frames).toHaveLength(0);
    expect(h.client.getStatus().phase).toBe("connecting");
  });

  it("does not latch live when a frame finishes decrypting after the socket closed", async () => {
    const h = harness();
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    expect(h.client.getStatus().phase).toBe("live");

    // A frame is in flight when the socket drops: its completion must not restore
    // a `live` phase on a dead socket (the capital-committing circuit breaker
    // would otherwise stay open on stale state).
    h.decryptor.delayFor = () => 20;
    const pending = h.client.ingest(envelope(1, delta(2)));
    h.client.noteDisconnected("socket closed", 2_000);
    await pending;
    h.client.flushAll();
    expect(h.client.getStatus().phase).toBe("reconnecting");
    expect(h.frames.map((f) => f.seq)).toEqual([0]);
  });

  it("watchdog degrades a latched live phase when frames stop arriving", async () => {
    let now = 1_000;
    const h = harness(8, () => now);
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    await h.client.ingest(envelope(1, delta(2)));
    h.client.flushDue();
    expect(h.client.getStatus().phase).toBe("live");

    now += FRAME_FRESHNESS_TTL_MS + 1;
    h.client.watchdog();
    expect(h.client.getStatus().phase).toBe("degraded");
  });

  it("refuses a replayed frame whose authenticated server time is stale (BR-15)", async () => {
    let now = 100_000;
    const h = harness(64, () => now, () => now);
    h.client.start();
    await h.client.ingest(envelope(0, { ...snapshot(1), server_time_ms: now }));
    h.client.flushDue();
    expect(h.client.getStatus().phase).toBe("live");

    // A relay withholds frames and replays a captured delta long after capture.
    // Its AEAD-authenticated server clock is older than the freshness window, so
    // it must not refresh `lastFrameAtMs` (keeping the circuit breaker open) or
    // latch live.
    now += FRAME_FRESHNESS_TTL_MS + 1;
    await h.client.ingest(
      envelope(1, { ...delta(2), server_time_ms: now - FRAME_FRESHNESS_TTL_MS - 1 }),
    );
    h.client.flushAll();
    expect(h.frames.map((f) => f.seq)).toEqual([0]);
    expect(h.resyncs.at(-1)?.reason).toBe("freshness");
    expect(h.errors.at(-1)?.code).toBe("freshness");
    expect(h.client.getStatus().phase).not.toBe("live");
  });

  it("refuses a frame whose authenticated server time regresses (BR-15)", async () => {
    const h = harness(64, () => 100_000, () => 100_000);
    h.client.start();
    await h.client.ingest(envelope(0, { ...snapshot(1), server_time_ms: 100_050 }));
    h.client.flushDue();
    expect(h.client.getStatus().phase).toBe("live");

    // An older authenticated frame cannot roll state back or refresh freshness.
    await h.client.ingest(envelope(1, { ...delta(2), server_time_ms: 100_010 }));
    h.client.flushAll();
    expect(h.frames.map((f) => f.seq)).toEqual([0]);
    expect(h.resyncs.at(-1)?.reason).toBe("freshness");
  });

  it("does not enforce replay freshness when the backend omits server_time_ms", async () => {
    let now = 100_000;
    const h = harness(64, () => now, () => now);
    h.client.start();
    await h.client.ingest(envelope(0, snapshot(1)));
    h.client.flushDue();
    expect(h.client.getStatus().phase).toBe("live");
    // Without the authenticated clock the client keeps the previous behaviour.
    now += FRAME_FRESHNESS_TTL_MS + 1;
    await h.client.ingest(envelope(1, delta(2)));
    h.client.flushAll();
    expect(h.frames.map((f) => f.seq)).toEqual([0, 1]);
  });
});
