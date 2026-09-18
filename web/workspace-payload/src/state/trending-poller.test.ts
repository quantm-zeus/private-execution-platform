import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createTrendingPoller } from "./trending-poller";

describe("createTrendingPoller", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("polls at the active cadence (2s) and stops on dispose", async () => {
    const refresh = vi.fn();
    const poller = createTrendingPoller({
      refresh,
      isReady: () => true,
      isHidden: () => false,
      isDegraded: () => false,
    });
    poller.start();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(refresh).toHaveBeenCalledTimes(5);
    poller.dispose();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(refresh).toHaveBeenCalledTimes(5);
  });

  it("never overlaps a slow in-flight refresh", async () => {
    let resolve!: () => void;
    const pending = new Promise<void>((r) => {
      resolve = r;
    });
    const refresh = vi.fn(() => pending);
    const poller = createTrendingPoller({
      refresh,
      isReady: () => true,
      isHidden: () => false,
      isDegraded: () => false,
    });
    poller.start();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(refresh).toHaveBeenCalledTimes(1);
    // A stalled request must not stack further requests behind it.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(refresh).toHaveBeenCalledTimes(1);
    resolve();
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(refresh).toHaveBeenCalledTimes(2);
    poller.dispose();
  });

  it("coalesces a kick while a refresh is in flight instead of overlapping", async () => {
    let resolve!: () => void;
    const pending = new Promise<void>((r) => {
      resolve = r;
    });
    let concurrent = 0;
    let maxConcurrent = 0;
    const refresh = vi.fn(async () => {
      concurrent += 1;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await pending;
      concurrent -= 1;
    });
    const poller = createTrendingPoller({
      refresh,
      isReady: () => true,
      isHidden: () => false,
      isDegraded: () => false,
    });
    poller.start();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(refresh).toHaveBeenCalledTimes(1);
    // A kick (e.g. the tab became visible) while the refresh is still settling
    // must be coalesced, never started concurrently.
    poller.kick();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(maxConcurrent).toBe(1);
    resolve();
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(0);
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(maxConcurrent).toBe(1);
    poller.dispose();
  });

  it("defers while hidden and resumes immediately when visible", async () => {
    let hidden = true;
    const refresh = vi.fn();
    const poller = createTrendingPoller({
      refresh,
      isReady: () => true,
      isHidden: () => hidden,
      isDegraded: () => false,
    });
    poller.start();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(refresh).not.toHaveBeenCalled();
    // Still hidden after a long wait: the deferred timer keeps deferring.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(refresh).not.toHaveBeenCalled();
    hidden = false;
    poller.kick();
    await vi.advanceTimersByTimeAsync(0);
    expect(refresh).toHaveBeenCalledTimes(1);
    poller.dispose();
  });

  it("backs off exponentially while degraded, capped", async () => {
    const refresh = vi.fn();
    const poller = createTrendingPoller({
      refresh,
      isReady: () => true,
      isHidden: () => false,
      isDegraded: () => true,
      intervalMs: 2_000,
      degradedIntervalMs: 1_000,
      maxBackoffMs: 4_000,
    });
    poller.start();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(refresh).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(refresh).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(refresh).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(4_000);
    expect(refresh).toHaveBeenCalledTimes(4);
    // The cap holds: the next degraded tick is 4s, not 8s.
    await vi.advanceTimersByTimeAsync(4_000);
    expect(refresh).toHaveBeenCalledTimes(5);
    poller.dispose();
  });

  it("does not poll while the command channel is not ready", async () => {
    let ready = false;
    const refresh = vi.fn();
    const poller = createTrendingPoller({
      refresh,
      isReady: () => ready,
      isHidden: () => false,
      isDegraded: () => false,
    });
    poller.start();
    await vi.advanceTimersByTimeAsync(20_000);
    expect(refresh).not.toHaveBeenCalled();
    ready = true;
    await vi.advanceTimersByTimeAsync(2_000);
    expect(refresh).toHaveBeenCalledTimes(1);
    poller.dispose();
  });
});
