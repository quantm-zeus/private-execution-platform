import { describe, expect, it } from "vitest";
import {
  createSubmissionKeyTracker,
  isIndeterminateOutcome,
  newIdempotencyKey,
} from "./idempotency";

describe("isIndeterminateOutcome", () => {
  it("treats transport/protocol failures as ambiguous (retry must dedupe)", () => {
    for (const code of ["network", "protocol", "unknown", "cancelled"] as const) {
      expect(isIndeterminateOutcome(code)).toBe(true);
    }
  });

  it("treats a retryable server error as ambiguous but a non-retryable one as determinate", () => {
    expect(isIndeterminateOutcome("server", true)).toBe(true);
    // Backwards-compatible default: an unspecified server error is ambiguous.
    expect(isIndeterminateOutcome("server")).toBe(true);
    // A 4xx validation rejection definitely did not commit: rotate the key.
    expect(isIndeterminateOutcome("server", false)).toBe(false);
  });

  it("treats explicit backend rejections as determinate (retry is a new write)", () => {
    for (const code of ["auth", "capability_missing", "freshness"] as const) {
      expect(isIndeterminateOutcome(code)).toBe(false);
      // An explicit non-retryable rejection is determinate too.
      expect(isIndeterminateOutcome(code, false)).toBe(false);
    }
  });

  it("honours an explicit retryable flag on any code (no duplicate write)", () => {
    // A transient backend failure can be surfaced under a capability code while
    // the write may still have committed, so `retryable:true` must keep the key.
    for (const code of ["auth", "capability_missing", "freshness", "protocol", "server"] as const) {
      expect(isIndeterminateOutcome(code, true)).toBe(true);
    }
  });
});

describe("newIdempotencyKey", () => {
  it("is prefixed and unique per call", () => {
    const first = newIdempotencyKey("limit");
    const second = newIdempotencyKey("limit");
    expect(first.startsWith("limit-")).toBe(true);
    expect(first).not.toBe(second);
  });
});

describe("createSubmissionKeyTracker", () => {
  it("is stable while the signature is unchanged", () => {
    const tracker = createSubmissionKeyTracker("twap");
    const first = tracker.keyFor("{}");
    expect(tracker.keyFor("{}")).toBe(first);
    expect(tracker.keyFor('{"amount":"5"}')).not.toBe(first);
  });

  it("rotates after a successful submission so a repeat is a new write", () => {
    const tracker = createSubmissionKeyTracker("withdraw");
    const first = tracker.keyFor("payload");
    tracker.clear();
    const second = tracker.keyFor("payload");
    expect(second).not.toBe(first);
  });

  it("reuses the retry key until an explicit clear", () => {
    const tracker = createSubmissionKeyTracker("rfq");
    const key = tracker.keyFor("a");
    // Simulate transport failures: no clear is called between retries.
    expect(tracker.keyFor("a")).toBe(key);
    expect(tracker.keyFor("a")).toBe(key);
  });
});
