// BR-5 handoff gate: the one-shot, token-bound delivery decision for the
// shell-to-payload session keys.
//
// The cleartext shell establishes the HPKE session and decrypts the artifact,
// then must hand the payload directional AEAD keys over the same-document
// channel. The sandbox permits the framed document to self-navigate, so a bare
// `workspace-ready` ping is not proof of identity: the shell injects a fresh
// random token into the payload document and only releases the keys when the
// ping echoes it. Delivery is also one-shot per unlock.
//
// Keeping this decision in a dependency-free class (no DOM, no WASM) makes the
// security control directly testable instead of only reachable through a full
// unlock, and keeps the runtime's cleanup honest: `disarm()` drops every
// reference so `lock()` cannot leave a takeable session behind.

/** BR-5 session material handed to the payload over the same-document channel. */
export interface ShellSessionKeys {
  readonly kid: string;
  readonly s2cKeyB64: string;
  readonly c2sKeyB64: string;
}

/**
 * One-shot, token-bound key handoff gate.
 *
 * `arm` is called once per unlock with the fresh session keys and the token
 * injected into the payload document. `take` returns the keys at most once and
 * only for the exact token; every other case (not armed, already delivered,
 * missing/empty/non-string/wrong token) returns `null`. `disarm` drops all
 * references and refuses every subsequent `take` until re-armed.
 */
export class HandoffGate {
  private session: ShellSessionKeys | null = null;
  private token: string | null = null;
  private delivered = false;

  /** Arm the gate with a fresh per-unlock session and binding token. */
  arm(session: ShellSessionKeys, token: string): void {
    this.session = session;
    this.token = token;
    this.delivered = false;
  }

  /**
   * Take the keys exactly once, only for the matching token.
   *
   * The comparison is deliberately not constant-time: the token is a
   * same-document capability, not a network secret, and both operands are
   * already known to the compared documents.
   */
  take(token: unknown): ShellSessionKeys | null {
    if (this.session === null || this.token === null) return null;
    if (this.delivered) return null;
    if (typeof token !== "string" || token.length === 0) return null;
    if (token !== this.token) return null;
    this.delivered = true;
    return this.session;
  }

  /** Drop every reference. A disarmed gate refuses every `take`. */
  disarm(): void {
    this.session = null;
    this.token = null;
    this.delivered = false;
  }
}
