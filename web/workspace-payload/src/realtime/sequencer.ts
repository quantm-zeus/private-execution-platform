/**
 * Realtime sequence tracking.
 *
 * The cleartext envelope sequence is observed *before* decryption so gaps are
 * detected cheaply. A gap, replay or duplicate never mutates state: the worker
 * drops the frame and requests a snapshot resync.
 */
export type SequenceDecision =
  | { readonly kind: "accept"; readonly expectedAfter: number }
  | { readonly kind: "duplicate"; readonly expected: number }
  | { readonly kind: "gap"; readonly expected: number; readonly received: number }
  | { readonly kind: "await_snapshot"; readonly expected: number | null };

export class FrameSequencer {
  private expected: number | null = null;
  private resyncing = false;
  /**
   * Highest sequence ever applied. Preserved across `beginResync` and
   * `beginReconnect` so a replayed older snapshot cannot roll state backward,
   * but cleared by `reset` (a genuinely new session/key may restart the
   * sequence space).
   */
  private applied: number | null = null;

  /** Full reset for a NEW session (fresh key/kid): the epoch may restart. */
  reset(): void {
    this.expected = null;
    this.resyncing = false;
    this.applied = null;
  }

  get expectedSeq(): number | null {
    return this.expected;
  }

  get lastAppliedSeq(): number | null {
    return this.applied;
  }

  get isResyncing(): boolean {
    return this.resyncing;
  }

  beginResync(): void {
    this.resyncing = true;
  }

  /**
   * Reconnect within the SAME session. The rollback high-water mark is kept:
   * an untrusted relay that captures a genuine snapshot, drops the socket and
   * replays that snapshot first on the new connection must not roll the client
   * backward. Recovery accepts `seq >= applied` (equal re-baselines without a
   * rollback); `seq < applied` is refused. A genuine server-side sequence
   * restart is a protocol change that must arrive through a new session key,
   * not silently through this reconnect.
   */
  beginReconnect(): void {
    this.resyncing = true;
  }

  /** A snapshot resets the baseline: the next accepted sequence is `seq + 1`. */
  onSnapshot(seq: number): void {
    this.expected = seq + 1;
    this.applied = seq;
    this.resyncing = false;
  }

  /**
   * Advance the rollback high-water mark. This must be called **only after** the
   * frame at `seq` has authenticated (AEAD verified) and decoded. The cleartext
   * sequence observed in `observe` is attacker-controllable, so advancing the
   * mark there would let a single injected/tampered envelope pin `applied`
   * above the genuine stream and permanently refuse the recovery snapshot.
   */
  noteApplied(seq: number): void {
    this.applied = seq;
  }

  observe(seq: number): SequenceDecision {
    if (this.resyncing) return { kind: "await_snapshot", expected: this.expected };
    if (this.expected === null) {
      // The first frame establishes the expected baseline; the client separately
      // enforces that the first frame is a snapshot. `applied` is deliberately
      // not set here: the frame has not been authenticated yet.
      this.expected = seq + 1;
      return { kind: "accept", expectedAfter: this.expected };
    }
    if (seq < this.expected) return { kind: "duplicate", expected: this.expected };
    if (seq > this.expected) {
      this.resyncing = true;
      return { kind: "gap", expected: this.expected, received: seq };
    }
    this.expected = seq + 1;
    return { kind: "accept", expectedAfter: this.expected };
  }
}
