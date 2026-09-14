import { describe, expect, it } from "vitest";
import { bytesToBase64 } from "../core/base64";
import { decodeInnerFrame } from "./decoder";
import { parseEnvelopeText, validateEnvelope } from "./envelope";

const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

describe("validateEnvelope / parseEnvelopeText", () => {
  const valid = {
    kid: "kid-1",
    nonce: bytesToBase64(new Uint8Array(12)),
    sequence: 3,
    ciphertext: bytesToBase64(new Uint8Array(20)),
  };

  it("accepts a well-formed generic envelope", () => {
    expect(validateEnvelope(valid)).toEqual(valid);
    expect(parseEnvelopeText(JSON.stringify(valid)).sequence).toBe(3);
  });

  it("rejects a non-12-byte nonce", () => {
    expect(() => validateEnvelope({ ...valid, nonce: bytesToBase64(new Uint8Array(8)) })).toThrowError();
  });

  it("rejects a negative or unsafe sequence", () => {
    expect(() => validateEnvelope({ ...valid, sequence: -1 })).toThrowError();
    expect(() => validateEnvelope({ ...valid, sequence: 1.5 })).toThrowError();
    expect(() => validateEnvelope({ ...valid, sequence: Number.MAX_SAFE_INTEGER + 2 })).toThrowError();
  });

  it("rejects an oversize ciphertext", () => {
    expect(() =>
      validateEnvelope({ ...valid, ciphertext: bytesToBase64(new Uint8Array(1024 * 1024 + 1)) }),
    ).toThrowError();
  });

  it("rejects malformed JSON without leaking the body", () => {
    expect(() => parseEnvelopeText("{not json")).toThrowError();
  });
});

describe("decodeInnerFrame", () => {
  it("normalizes a delta and derives the channel priority", () => {
    const frame = decodeInnerFrame(
      encode({ op: "delta", channel: "ohlcv", entity_key: "ohlcv:BASE:SOL", slot: 9, source_age_ms: 12, payload: { c: 1 } }),
      7,
    );
    expect(frame).toMatchObject({ seq: 7, op: "delta", channel: "ohlcv", priority: 1, slot: 9, sourceAgeMs: 12 });
  });

  it("honors an explicit priority inside the ciphertext", () => {
    const frame = decodeInnerFrame(encode({ op: "delta", channel: "market", priority: 0, payload: {} }), 1);
    expect(frame.priority).toBe(0);
  });

  it("rejects unknown operations and channels", () => {
    expect(() => decodeInnerFrame(encode({ op: "trade", channel: "ohlcv", payload: {} }), 1)).toThrowError();
    expect(() => decodeInnerFrame(encode({ op: "delta", channel: "evil", payload: {} }), 1)).toThrowError();
  });

  it("rejects state frames without a payload", () => {
    expect(() => decodeInnerFrame(encode({ op: "delta", channel: "ohlcv" }), 1)).toThrowError();
  });

  it("defaults the coalescing key and tolerates missing metadata", () => {
    const frame = decodeInnerFrame(encode({ op: "heartbeat", channel: "system" }), 2);
    expect(frame.entityKey).toBe("system:default");
    expect(frame.slot).toBeNull();
    expect(frame.sourceAgeMs).toBe(0);
  });

  it("rejects non-UTF8 and oversize payloads", () => {
    expect(() => decodeInnerFrame(new Uint8Array([0xff, 0xfe]), 1)).toThrowError();
    expect(() => decodeInnerFrame(new Uint8Array(512 * 1024 + 1), 1)).toThrowError();
  });
});
