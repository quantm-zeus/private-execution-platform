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

  reset(): void {
    this.expected = null;
    this.resyncing = false;
  }

  get expectedSeq(): number | null {
    return this.expected;
  }

  get isResyncing(): boolean {
    return this.resyncing;
  }

  beginResync(): void {
    this.resyncing = true;
  }

  /** A snapshot resets the baseline: the next accepted sequence is `seq + 1`. */
  onSnapshot(seq: number): void {
    this.expected = seq + 1;
    this.resyncing = false;
  }

  observe(seq: number): SequenceDecision {
    if (this.resyncing) return { kind: "await_snapshot", expected: this.expected };
    if (this.expected === null) {
      // The first frame establishes the baseline; the client separately
      // enforces that the first frame is a snapshot.
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
