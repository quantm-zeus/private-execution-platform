// Shared bounded-body reader for the neutral private transport.
//
// Every private response is untrusted relay output, so it must be size-bounded
// *before* it is materialized/parsed. The command path and the bootstrap path
// previously disagreed (bootstrap used an unbounded `response.json()`), which
// let a compromised relay OOM the main thread with a multi-gigabyte body.

import { workspaceError } from "../core/errors";

/** Hard ceiling for any private JSON response body (bootstrap, command, …). */
export const MAX_PRIVATE_BODY_BYTES = 2 * 1024 * 1024;

/** Read the response body as text with a hard byte ceiling before parsing. */
export async function readBoundedText(
  response: Response,
  maxBytes: number = MAX_PRIVATE_BODY_BYTES,
): Promise<string> {
  const contentLength = response.headers?.get?.("content-length");
  if (
    contentLength !== null &&
    contentLength !== undefined &&
    Number(contentLength) > maxBytes
  ) {
    throw workspaceError("protocol", "Response exceeded the size limit.");
  }
  const body = response.body;
  if (body && typeof body.getReader === "function") {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          total += value.byteLength;
          if (total > maxBytes) {
            throw workspaceError("protocol", "Response exceeded the size limit.");
          }
          chunks.push(value);
        }
      }
    } finally {
      try {
        reader.releaseLock();
      } catch {
        // reader already released
      }
    }
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder().decode(merged);
  }
  if (typeof response.text === "function") {
    const text = await response.text();
    if (text.length > maxBytes) {
      throw workspaceError("protocol", "Response exceeded the size limit.");
    }
    return text;
  }
  throw workspaceError("protocol", "Response body was unreadable.");
}

/** Read and parse a JSON body under the byte ceiling. */
export async function readBoundedJson(
  response: Response,
  maxBytes: number = MAX_PRIVATE_BODY_BYTES,
): Promise<unknown> {
  const contentLength = response.headers?.get?.("content-length");
  if (
    contentLength !== null &&
    contentLength !== undefined &&
    Number(contentLength) > maxBytes
  ) {
    throw workspaceError("protocol", "Response exceeded the size limit.");
  }
  if (typeof response.text === "function") {
    const text = await readBoundedText(response, maxBytes);
    try {
      return JSON.parse(text);
    } catch {
      throw workspaceError("protocol", "Response was not valid JSON.");
    }
  }
  // Test/minimal Response doubles may implement only `json()`; keep that path
  // working while the real transport always prefers the bounded text read.
  if (typeof response.json === "function") {
    try {
      return await response.json();
    } catch {
      throw workspaceError("protocol", "Response was not valid JSON.");
    }
  }
  throw workspaceError("protocol", "Response body was unreadable.");
}
