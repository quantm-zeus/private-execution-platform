import { describe, expect, it } from "vitest";
import { bytesToBase64 } from "../core/base64";
import { awaitHostSessionKey } from "./session-key";

const S2C = bytesToBase64(new Uint8Array(32).fill(7));

function handoff(source: MessageEventSource | null, origin = window.location.origin) {
  return new MessageEvent("message", {
    data: { type: "evergreen:session-key", kid: "kid-1", s2cKeyB64: S2C },
    source,
    origin,
  });
}

describe("awaitHostSessionKey", () => {
  it("accepts a same-document handoff and validates its shape", async () => {
    const promise = awaitHostSessionKey(100, window);
    window.dispatchEvent(handoff(window));
    await expect(promise).resolves.toMatchObject({ kid: "kid-1", s2cKeyB64: S2C });
  });

  it("refuses a synthesized message whose source is null", async () => {
    // An attacker-synthesizable event must never be able to install session keys.
    const promise = awaitHostSessionKey(25, window);
    window.dispatchEvent(handoff(null));
    await expect(promise).resolves.toBeNull();
  });

  it("refuses a handoff from a different origin even with a valid source", async () => {
    const promise = awaitHostSessionKey(25, window);
    window.dispatchEvent(handoff(window, "https://evil.example"));
    await expect(promise).resolves.toBeNull();
  });

  it("resolves null as soon as it is aborted", async () => {
    const controller = new AbortController();
    const promise = awaitHostSessionKey(10_000, window, controller.signal);
    controller.abort();
    await expect(promise).resolves.toBeNull();
  });

  it("resolves null after the timeout without leaking a listener", async () => {
    await expect(awaitHostSessionKey(10, window)).resolves.toBeNull();
  });
});
