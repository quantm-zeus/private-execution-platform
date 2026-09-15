import { base64ToBytes, bytesToBase64, utf8Encode, utf8Decode } from "../core/base64";
import { toWorkspaceErrorShape, workspaceError } from "../core/errors";
import type { WorkspaceErrorShape } from "../core/types";
import type { SessionDecryptor } from "../realtime/decryptor";
import { validateEnvelope } from "../realtime/envelope";
import type { SessionSealer } from "../realtime/sealer";
import { assertNeutralUrl } from "./paths";

export interface CommandSendOptions {
  readonly idempotencyKey?: string;
  readonly signal?: AbortSignal;
}

/**
 * A command that never settles would leave the UI stuck in a pending state that
 * is indistinguishable from an UNKNOWN outcome. Bound the wait; a timeout is an
 * ambiguous failure (the request may have left the browser), so callers treat it
 * as indeterminate and keep the idempotency key.
 */
const COMMAND_TIMEOUT_MS = 15_000;

/**
 * Upper bound on the *cleartext* response body before parsing. The envelope
 * validator caps the ciphertext at 1 MiB, but a compromised relay could still
 * return a multi-gigabyte JSON document; the body is streamed and bounded so the
 * main thread cannot be OOM'd before validation runs.
 */
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

/**
 * Operations that commit capital. A bare HTTP status is relay-controlled
 * metadata, not an authenticated rejection: for these operations it can never
 * prove the command did not commit, so a status-only failure must stay
 * indeterminate (the caller keeps its idempotency key and surfaces UNKNOWN).
 * Backends prove a rejection by returning a typed error *inside* the AEAD
 * envelope (BR-3), which is classified from the authenticated body instead.
 */
const WRITE_OPS: ReadonlySet<string> = new Set([
  "execute_market_order",
  "place_limit_order",
  "cancel_order",
  "start_twap",
  "submit_rfq",
  "request_withdrawal",
  // Changing a wallet safety limit is a security write: a status-only failure
  // proves nothing about whether it committed, so it stays indeterminate.
  "set_wallet_limits",
]);

/**
 * Per-request random challenge. It travels only inside the AEAD request and must
 * be echoed inside the AEAD response, so a captured stream frame (which has no
 * `request_id`) or a replayed older command response cannot be substituted for
 * the answer to this request.
 */
function randomRequestId(): string {
  const cryptoObj: Crypto | undefined = globalThis.crypto;
  if (cryptoObj !== undefined && typeof cryptoObj.randomUUID === "function") {
    return cryptoObj.randomUUID();
  }
  // The per-request challenge is an anti-replay nonce; a predictable value would
  // weaken the authenticated-echo binding, so a deployment without `crypto`
  // fails closed rather than using `Math.random()`.
  if (cryptoObj !== undefined && typeof cryptoObj.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    cryptoObj.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  throw workspaceError(
    "protocol",
    "A cryptographically secure request id could not be generated.",
  );
}

function withTimeout(signal: AbortSignal | undefined, ms: number): AbortSignal | undefined {
  if (typeof AbortSignal === "undefined" || typeof AbortSignal.timeout !== "function") {
    return signal;
  }
  const timeout = AbortSignal.timeout(ms);
  if (signal === undefined) return timeout;
  if (typeof AbortSignal.any === "function") return AbortSignal.any([signal, timeout]);
  // `AbortSignal.any` is unavailable: never drop the timeout (the module's whole
  // point is a bounded wait). Bridge both so either can abort.
  const controller = new AbortController();
  const abort = (reason: unknown): void => {
    if (!controller.signal.aborted) controller.abort(reason);
  };
  if (signal.aborted) abort(signal.reason);
  else signal.addEventListener("abort", () => abort(signal.reason), { once: true });
  timeout.addEventListener("abort", () => abort(timeout.reason), { once: true });
  return controller.signal;
}

/**
 * Neutral encrypted command channel. Default is fail-closed: with no backend
 * capability the workspace must never pretend a command succeeded.
 */
export interface CommandClient {
  send<T>(op: string, payload: unknown, options?: CommandSendOptions): Promise<T>;
}

export class UnavailableCommandClient implements CommandClient {
  async send<T>(): Promise<T> {
    throw workspaceError("capability_missing", "Private command channel is not available.", {
      detail: "BR-3",
    });
  }
}

export interface EncryptedCommandClientOptions {
  readonly sealer: SessionSealer;
  readonly decryptor: SessionDecryptor;
  readonly kid: string;
  readonly baseUrl: string;
  readonly fetchFn?: typeof fetch;
}

/**
 * Encrypts the operation type and payload inside the AEAD and posts the generic
 * envelope to `/v1/command`. Cleartext contains only kid/sequence/nonce/ciphertext.
 */
export class EncryptedCommandClient implements CommandClient {
  private sequence = 0;

  constructor(private readonly options: EncryptedCommandClientOptions) {}

  async send<T>(op: string, payload: unknown, options: CommandSendOptions = {}): Promise<T> {
    const url = assertNeutralUrl("/v1/command", this.options.baseUrl);
    const fetchFn = this.options.fetchFn ?? (typeof fetch !== "undefined" ? fetch : undefined);
    if (!fetchFn) throw workspaceError("capability_missing", "Command transport is unavailable.");

    const sequence = this.sequence++;
    const requestId = randomRequestId();
    const plaintext = utf8Encode(
      JSON.stringify({
        op,
        payload,
        request_id: requestId,
        idempotency_key: options.idempotencyKey ?? null,
      }),
    );
    let sealed;
    try {
      sealed = await this.options.sealer.seal({ kid: this.options.kid, sequence }, plaintext);
    } finally {
      plaintext.fill(0);
    }

    const envelopeBody = JSON.stringify({
      kid: this.options.kid,
      sequence,
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext,
    });

    let response: Response;
    try {
      response = await fetchFn(url.toString(), {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: envelopeBody,
        signal: withTimeout(options.signal, COMMAND_TIMEOUT_MS),
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw workspaceError("cancelled", "Command cancelled.", { retryable: true });
      }
      throw workspaceError("network", "Command transport failed.", { retryable: true });
    }

    if (!response.ok) {
      // Only an AEAD-authenticated error body is trustworthy. A bare status line
      // is relay-controlled and, for a write, proves nothing about whether the
      // command committed.
      const authenticated = await this.tryAuthenticatedError(response, sequence, requestId, op);
      if (authenticated) throw authenticated;
      throw mapCommandFailure(response.status, op);
    }

    const envelope = await readEnvelope(response);
    // Bind the response to this request by both the envelope sequence and the
    // authenticated request challenge: a replayed older response (different
    // request_id) or a captured stream frame (no request_id) is rejected.
    if (envelope.sequence !== sequence) {
      throw workspaceError("protocol", "Command response sequence mismatch.", {
        retryable: false,
        detail: `expected ${sequence}, received ${envelope.sequence}`,
      });
    }
    const decrypted = await this.options.decryptor.decrypt(envelope);
    try {
      let body: unknown;
      try {
        body = JSON.parse(utf8Decode(decrypted));
      } catch {
        throw workspaceError("protocol", "Command response was not valid JSON.");
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        throw workspaceError("protocol", "Command response was malformed.");
      }
      const record = body as Record<string, unknown>;
      if (record.request_id !== requestId) {
        throw workspaceError(
          "protocol",
          "Command response was not bound to this request.",
          { retryable: false, detail: "request binding" },
        );
      }
      if ("error" in record && record.error) {
        throw mapCommandError(record.error, op);
      }
      if (!("result" in record)) {
        throw workspaceError("protocol", "Command response carried no result.");
      }
      return record.result as T;
    } finally {
      decrypted.fill(0);
    }
  }

  /** Read and authenticate a typed rejection from a non-2xx response, if present. */
  private async tryAuthenticatedError(
    response: Response,
    sequence: number,
    requestId: string,
    op: string,
  ): Promise<WorkspaceErrorShape | null> {
    try {
      const envelope = await readEnvelope(response);
      if (envelope.sequence !== sequence || envelope.kid !== this.options.kid) return null;
      const decrypted = await this.options.decryptor.decrypt(envelope);
      try {
        const body = JSON.parse(utf8Decode(decrypted));
        // Bind to this request exactly like the success path. Without the
        // `request_id` echo, a captured authenticated envelope whose cleartext
        // sequence matches (e.g. a stream frame carrying a top-level `error`, or
        // a replayed response after the per-instance sequence restarts at 0)
        // could be accepted as a determinate rejection. Callers rotate their
        // idempotency key on a determinate rejection, so a substituted error
        // would turn a possibly-committed write into a fresh duplicate.
        if (
          body &&
          typeof body === "object" &&
          (body as { request_id?: unknown }).request_id === requestId &&
          "error" in body &&
          body.error
        ) {
          return mapCommandError((body as { error: unknown }).error, op);
        }
        return null;
      } finally {
        decrypted.fill(0);
      }
    } catch {
      return null;
    }
  }
}

function mapCommandFailure(status: number, op: string): WorkspaceErrorShape {
  // A status-only failure for a capital-committing write is indeterminate: the
  // relay controls the status line, so a forged 401/400/404/409 must not make the
  // client rotate its idempotency key and re-submit a possibly-committed order.
  if (WRITE_OPS.has(op)) {
    return workspaceError("unknown", "Command outcome could not be authenticated.", {
      retryable: true,
      detail: `command ${status}`,
    });
  }
  if (status === 401 || status === 403) {
    return workspaceError("auth", "Command is not authorized.", { retryable: false });
  }
  if (status === 404 || status === 501) {
    return workspaceError("capability_missing", "Command is not available.", { retryable: false });
  }
  if (status === 409) {
    return workspaceError("freshness", "Command rejected: state changed.", { retryable: true });
  }
  return workspaceError("server", "Command failed.", {
    retryable: status >= 500,
    detail: `command ${status}`,
  });
}

function mapCommandError(raw: unknown, op: string): WorkspaceErrorShape {
  if (raw && typeof raw === "object") {
    const record = raw as Record<string, unknown>;
    const code = typeof record.code === "string" ? record.code : "server";
    const message = typeof record.message === "string" ? record.message : "Command rejected.";
    const allowed = ["network", "auth", "capability_missing", "freshness", "protocol", "server", "cancelled", "unknown"];
    // An authenticated error that omits `retryable` is ambiguous. For a capital-
    // committing write, defaulting to a determinate rejection would let a 5xx
    // body missing the flag rotate the caller's idempotency key and re-submit a
    // possibly-committed order. Only an explicit `false` proves determinacy.
    const retryable = typeof record.retryable === "boolean" ? record.retryable : WRITE_OPS.has(op);
    return workspaceError(
      (allowed.includes(code) ? code : "server") as WorkspaceErrorShape["code"],
      message,
      { retryable },
    );
  }
  return toWorkspaceErrorShape(raw);
}

/** Read the response body with a hard byte ceiling before any parsing. */
async function readBoundedText(response: Response): Promise<string> {
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
          if (total > MAX_RESPONSE_BYTES) {
            throw workspaceError("protocol", "Command response exceeded the size limit.");
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
    return utf8Decode(merged);
  }
  const text = await response.text();
  if (text.length > MAX_RESPONSE_BYTES) {
    throw workspaceError("protocol", "Command response exceeded the size limit.");
  }
  return text;
}

async function readJsonBody(response: Response): Promise<unknown> {
  const contentLength = response.headers?.get?.("content-length");
  if (contentLength !== null && contentLength !== undefined && Number(contentLength) > MAX_RESPONSE_BYTES) {
    throw workspaceError("protocol", "Command response exceeded the size limit.");
  }
  if (typeof response.text === "function") {
    const text = await readBoundedText(response);
    try {
      return JSON.parse(text);
    } catch {
      throw workspaceError("protocol", "Command response was not valid JSON.");
    }
  }
  if (typeof response.json === "function") {
    try {
      return await response.json();
    } catch {
      throw workspaceError("protocol", "Command response was not valid JSON.");
    }
  }
  throw workspaceError("protocol", "Command response was unreadable.");
}

async function readEnvelope(response: Response) {
  const raw = await readJsonBody(response);
  if (!raw || typeof raw !== "object") {
    throw workspaceError("protocol", "Command response was malformed.");
  }
  const record = raw as Record<string, unknown>;
  // Enforce the same strict envelope validation (1 MiB cap, 12-byte nonce,
  // safe sequence) as the realtime path.
  return validateEnvelope(record.envelope ?? record);
}

/** Test helper. */
export function encodePlaintext(value: unknown): Uint8Array {
  return utf8Encode(JSON.stringify(value));
}

/** Test helper. */
export function decodePlaintext(bytes: Uint8Array): unknown {
  return JSON.parse(utf8Decode(bytes));
}

/** Test helper. */
export function plaintextToBase64(value: unknown): string {
  return bytesToBase64(encodePlaintext(value));
}

/** Test helper. */
export function base64ToPlaintext(value: string): unknown {
  return decodePlaintext(base64ToBytes(value));
}
