import { describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64, utf8Encode } from "../core/base64";
import type { ConnectionStatus, WorkspaceErrorShape } from "../core/types";
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

function harness(capacity = 64): Harness {
  const decryptor = new FakeDecryptor();
  const frames: DecodedFrame[] = [];
  const statuses: ConnectionStatus[] = [];
  const resyncs: { reason: ResyncReason; fromSeq: number | null }[] = [];
  const errors: WorkspaceErrorShape[] = [];
  const client = new RealtimeClient({
    decryptor,
    expectedKid: KID,
    now: () => 1_000,
    batcher: new FrameBatcher({ capacity, flushMs: zeroFlush }),
    onFrames: (batch) => frames.push(...batch),
    onStatus: (status) => statuses.push(status),
    onResync: (reason, fromSeq) => resyncs.push({ reason, fromSeq }),
    onError: (error) => errors.push(error),
  });
  return { client, decryptor, frames, statuses, resyncs, errors };
}

const snapshot = (value: number) => ({ op: "snapshot", channel: "ohlcv", entity_key: "ohlcv:base", payload: { value } });
const delta = (value: number, entityKey = "ohlcv:base") => ({
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

  it("bounds the buffer under visual overflow without forcing a resync", async () => {
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
    expect(h.resyncs).toHaveLength(0);
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
});
