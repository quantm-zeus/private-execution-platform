import { describe, expect, it } from "vitest";
import { backoffDelay, DEFAULT_BACKOFF } from "./reconnect";

describe("backoffDelay", () => {
  const policy = { baseMs: 100, maxMs: 1_000, factor: 2, jitter: 0 };

  it("grows exponentially and caps at maxMs", () => {
    expect(backoffDelay(0, policy, () => 0)).toBe(100);
    expect(backoffDelay(1, policy, () => 0)).toBe(200);
    expect(backoffDelay(2, policy, () => 0)).toBe(400);
    expect(backoffDelay(3, policy, () => 0)).toBe(800);
    expect(backoffDelay(4, policy, () => 0)).toBe(1_000);
    expect(backoffDelay(50, policy, () => 0)).toBe(1_000);
  });

  it("applies equal jitter within the policy band", () => {
    const jittered = { ...policy, jitter: 0.5 };
    expect(backoffDelay(1, jittered, () => 0)).toBe(100);
    expect(backoffDelay(1, jittered, () => 1)).toBe(200);
    expect(backoffDelay(1, jittered, () => 0.5)).toBe(150);
  });

  it("never exceeds maxMs even with adversarial random", () => {
    expect(backoffDelay(10, DEFAULT_BACKOFF, () => 1)).toBeLessThanOrEqual(DEFAULT_BACKOFF.maxMs);
    expect(backoffDelay(-5, DEFAULT_BACKOFF, () => 1)).toBeLessThanOrEqual(DEFAULT_BACKOFF.maxMs);
  });
});
