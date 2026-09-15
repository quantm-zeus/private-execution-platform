import { afterEach, describe, expect, it, vi } from "vitest";

import { announceWorkspaceReady, readHandoffToken } from "./host";

/**
 * The payload side of the BR-5 handoff: it must echo the per-unlock token the
 * shell injected into the document, to the known same origin, and must never
 * broadcast it with a wildcard target. The shell withholds the keys unless the
 * echo is right, so a regression here would either strand the workspace offline
 * or leak the token to an unintended receiver.
 */
function setHandoffMeta(content?: string): void {
  document.head.innerHTML =
    content === undefined ? "" : `<meta name="evergreen-handoff" content="${content}">`;
}

/** jsdom's `window.parent` is a read-only accessor; replace it for the test. */
function setParent(parent: Window | { postMessage: (message: unknown, targetOrigin: string) => void }) {
  Object.defineProperty(window, "parent", { configurable: true, value: parent });
}

describe("host handoff channel", () => {
  afterEach(() => {
    document.head.innerHTML = "";
    setParent(window);
    vi.restoreAllMocks();
  });

  it("reads the injected token, and an absent meta is the empty string", () => {
    setHandoffMeta("tok-123");
    expect(readHandoffToken()).toBe("tok-123");

    setHandoffMeta(undefined);
    expect(readHandoffToken()).toBe("");

    setHandoffMeta("");
    expect(readHandoffToken()).toBe("");
  });

  it("echoes the token to the parent at the known origin, never a wildcard", () => {
    setHandoffMeta("tok-123");
    const postMessage = vi.fn();
    setParent({ postMessage });

    announceWorkspaceReady();

    expect(postMessage).toHaveBeenCalledTimes(1);
    expect(postMessage).toHaveBeenCalledWith(
      { type: "evergreen:workspace-ready", handoff: "tok-123" },
      window.location.origin,
    );
    // The second argument must be a concrete origin, not "*".
    expect(postMessage.mock.calls[0][1]).not.toBe("*");
  });

  it("does not post the ready ping when the payload is not framed", () => {
    setHandoffMeta("tok-123");
    const postMessage = vi.spyOn(window, "postMessage");
    // window.parent === window in a standalone document.
    expect(window.parent).toBe(window);

    announceWorkspaceReady();

    expect(postMessage).not.toHaveBeenCalled();
  });
});
