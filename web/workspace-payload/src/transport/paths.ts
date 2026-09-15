// Neutral first-party path allowlist.
//
// Architecture lock: the browser may only talk to our own origin over the
// neutral private-API paths. Every request helper routes through
// `assertNeutralUrl` so an accidental external/provider URL fails closed
// instead of leaking a private request to a third party.

import { workspaceError } from "../core/errors";

export const NEUTRAL_PATHS = [
  "/v1/bootstrap",
  "/v1/sync",
  "/v1/stream",
  "/v1/command",
  "/v1/blob",
] as const;

export type NeutralPath = (typeof NEUTRAL_PATHS)[number];

export function isNeutralPath(path: string): path is NeutralPath {
  return (NEUTRAL_PATHS as readonly string[]).includes(path);
}

/**
 * Resolve `input` against `base` and reject anything that is not a same-origin
 * neutral private-API URL. Returns the resolved URL.
 */
export function assertNeutralUrl(input: string, base: string): URL {
  let url: URL;
  let baseUrl: URL;
  try {
    baseUrl = new URL(base);
    url = new URL(input, baseUrl);
  } catch {
    throw workspaceError("protocol", "Invalid workspace endpoint.");
  }
  if (url.origin !== baseUrl.origin) {
    throw workspaceError("protocol", "Blocked cross-origin workspace request.", {
      detail: url.origin,
    });
  }
  if (url.username || url.password) {
    throw workspaceError("protocol", "Blocked credentialed workspace URL.");
  }
  if (!isNeutralPath(url.pathname)) {
    throw workspaceError("protocol", "Blocked non-neutral workspace path.", {
      detail: url.pathname,
    });
  }
  return url;
}

/**
 * Resolve a same-host websocket URL for the neutral stream path. Allows
 * `ws:`/`wss:` (scheme upgrade) only against the exact base host.
 */
export function assertNeutralStreamUrl(input: string, base: string): URL {
  let url: URL;
  let baseUrl: URL;
  try {
    baseUrl = new URL(base);
    url = new URL(input, baseUrl);
  } catch {
    throw workspaceError("protocol", "Invalid workspace stream endpoint.");
  }
  const websocketScheme = url.protocol === "ws:" || url.protocol === "wss:";
  if (!websocketScheme) {
    throw workspaceError("protocol", "Workspace stream endpoint must use ws/wss.");
  }
  if (url.host !== baseUrl.host) {
    throw workspaceError("protocol", "Blocked cross-origin workspace stream.", {
      detail: url.host,
    });
  }
  if (url.username || url.password) {
    throw workspaceError("protocol", "Blocked credentialed workspace stream URL.");
  }
  if (url.pathname !== "/v1/stream") {
    throw workspaceError("protocol", "Blocked non-neutral workspace stream path.");
  }
  return url;
}
