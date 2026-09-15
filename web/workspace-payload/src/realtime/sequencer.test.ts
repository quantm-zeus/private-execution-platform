import { describe, expect, it } from "vitest";
import { FrameSequencer } from "./sequencer";

describe("FrameSequencer", () => {
  it("accepts the first frame as the baseline", () => {
    const sequencer = new FrameSequencer();
    expect(sequencer.observe(1)).toEqual({ kind: "accept", expectedAfter: 2 });
  });

  it("requires a snapshot while resyncing", () => {
    const sequencer = new FrameSequencer();
    sequencer.onSnapshot(10);
    sequencer.observe(20);
    expect(sequencer.isResyncing).toBe(true);
    expect(sequencer.observe(21)).toEqual({ kind: "await_snapshot", expected: 11 });
  });

  it("accepts a contiguous snapshot then deltas", () => {
    const sequencer = new FrameSequencer();
    sequencer.onSnapshot(10);
    expect(sequencer.expectedSeq).toBe(11);
    expect(sequencer.observe(11)).toEqual({ kind: "accept", expectedAfter: 12 });
    expect(sequencer.observe(12)).toEqual({ kind: "accept", expectedAfter: 13 });
  });

  it("rejects duplicated and replayed sequences without advancing", () => {
    const sequencer = new FrameSequencer();
    sequencer.onSnapshot(5);
    expect(sequencer.observe(6)).toMatchObject({ kind: "accept" });
    expect(sequencer.observe(6)).toEqual({ kind: "duplicate", expected: 7 });
    expect(sequencer.observe(4)).toEqual({ kind: "duplicate", expected: 7 });
    expect(sequencer.expectedSeq).toBe(7);
  });

  it("reports a gap and refuses to advance", () => {
    const sequencer = new FrameSequencer();
    sequencer.onSnapshot(1);
    const decision = sequencer.observe(4);
    expect(decision).toEqual({ kind: "gap", expected: 2, received: 4 });
    expect(sequencer.isResyncing).toBe(true);
    expect(sequencer.observe(2)).toEqual({ kind: "await_snapshot", expected: 2 });
  });

  it("a snapshot resets the baseline after a resync", () => {
    const sequencer = new FrameSequencer();
    sequencer.onSnapshot(0);
    sequencer.observe(5);
    expect(sequencer.isResyncing).toBe(true);
    sequencer.onSnapshot(100);
    expect(sequencer.isResyncing).toBe(false);
    expect(sequencer.observe(101)).toEqual({ kind: "accept", expectedAfter: 102 });
  });

  it("advances the rollback high-water mark only after authentication", () => {
    const sequencer = new FrameSequencer();
    // A cleartext observation (pre-AEAD) must never move the rollback mark: the
    // sequence is attacker-controllable until the frame is authenticated.
    expect(sequencer.observe(5)).toMatchObject({ kind: "accept" });
    expect(sequencer.lastAppliedSeq).toBeNull();
    sequencer.noteApplied(5);
    expect(sequencer.lastAppliedSeq).toBe(5);
    expect(sequencer.observe(6)).toMatchObject({ kind: "accept" });
    expect(sequencer.lastAppliedSeq).toBe(5);
    sequencer.onSnapshot(9);
    expect(sequencer.lastAppliedSeq).toBe(9);
  });
});
