import { describe, expect, it } from "vitest";
import { assertNeutralStreamUrl, assertNeutralUrl, isNeutralPath } from "./paths";

const BASE = "https://workspace.example";

describe("neutral path allowlist", () => {
  it("accepts the neutral private-API paths", () => {
    for (const path of ["/v1/bootstrap", "/v1/sync", "/v1/stream", "/v1/command", "/v1/blob"]) {
      expect(isNeutralPath(path)).toBe(true);
      expect(() => assertNeutralUrl(path, BASE)).not.toThrow();
    }
  });

  it("rejects provider / non-neutral paths", () => {
    for (const path of ["/api/quote", "/v1/other", "/internal/artifact", "https://gmgn.ai/x"]) {
      expect(() => assertNeutralUrl(path, BASE)).toThrowError();
    }
  });

  it("rejects cross-origin URLs even on a neutral path", () => {
    expect(() => assertNeutralUrl("https://evil.example/v1/bootstrap", BASE)).toThrowError(
      /cross-origin/i,
    );
  });

  it("rejects credentialed URLs", () => {
    expect(() => assertNeutralUrl("https://user:pass@workspace.example/v1/bootstrap", BASE)).toThrowError();
  });

  it("resolves relative neutral paths against the base origin", () => {
    const url = assertNeutralUrl("/v1/sync", BASE);
    expect(url.origin).toBe(BASE);
    expect(url.pathname).toBe("/v1/sync");
  });

  it("validates websocket stream URLs by host and path", () => {
    expect(() => assertNeutralStreamUrl("wss://workspace.example/v1/stream", BASE)).not.toThrow();
    expect(() => assertNeutralStreamUrl("wss://evil.example/v1/stream", BASE)).toThrowError();
    expect(() => assertNeutralStreamUrl("wss://workspace.example/v1/command", BASE)).toThrowError();
    expect(() => assertNeutralStreamUrl("https://workspace.example/v1/stream", BASE)).toThrowError();
  });
});
