import { base64ToBytes, bytesToBase64, utf8Encode, utf8Decode } from "../core/base64";
import { toWorkspaceErrorShape, workspaceError } from "../core/errors";
import type { WorkspaceErrorShape } from "../core/types";
import type { SessionDecryptor } from "../realtime/decryptor";
import type { SessionSealer } from "../realtime/sealer";
import { assertNeutralUrl } from "./paths";

export interface CommandSendOptions {
  readonly idempotencyKey?: string;
  readonly signal?: AbortSignal;
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
    const plaintext = utf8Encode(
      JSON.stringify({
        op,
        payload,
        idempotency_key: options.idempotencyKey ?? null,
      }),
    );
    let sealed;
    try {
      sealed = await this.options.sealer.seal({ kid: this.options.kid, sequence }, plaintext);
    } finally {
      plaintext.fill(0);
    }

    let response: Response;
    try {
      response = await fetchFn(url.toString(), {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          kid: this.options.kid,
          sequence,
          nonce: sealed.nonce,
          ciphertext: sealed.ciphertext,
        }),
        signal: options.signal,
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw workspaceError("cancelled", "Command cancelled.", { retryable: true });
      }
      throw workspaceError("network", "Command transport failed.", { retryable: true });
    }

    if (!response.ok) {
      throw mapCommandFailure(response.status);
    }

    const envelope = await readEnvelope(response);
    const decrypted = await this.options.decryptor.decrypt(envelope);
    try {
      const body = JSON.parse(utf8Decode(decrypted));
      if (body && typeof body === "object" && "error" in body && body.error) {
        throw mapCommandError(body.error);
      }
      return (body?.result ?? body) as T;
    } finally {
      decrypted.fill(0);
    }
  }
}

function mapCommandFailure(status: number): WorkspaceErrorShape {
  const error = workspaceError("server", "Command failed.", {
    retryable: status >= 500,
    detail: `command ${status}`,
  });
  if (status === 401 || status === 403) {
    return { code: "auth", message: "Command is not authorized.", retryable: false };
  }
  if (status === 404 || status === 501) {
    return { code: "capability_missing", message: "Command is not available.", retryable: false };
  }
  if (status === 409) {
    return { code: "freshness", message: "Command rejected: state changed.", retryable: true };
  }
  return error.toShape();
}

function mapCommandError(raw: unknown): WorkspaceErrorShape {
  if (raw && typeof raw === "object") {
    const record = raw as Record<string, unknown>;
    const code = typeof record.code === "string" ? record.code : "server";
    const message = typeof record.message === "string" ? record.message : "Command rejected.";
    const allowed = ["network", "auth", "capability_missing", "freshness", "protocol", "server", "cancelled", "unknown"];
    return {
      code: (allowed.includes(code) ? code : "server") as WorkspaceErrorShape["code"],
      message,
      retryable: record.retryable === true,
    };
  }
  return toWorkspaceErrorShape(raw);
}

async function readEnvelope(response: Response) {
  let raw: unknown;
  try {
    raw = await response.json();
  } catch {
    throw workspaceError("protocol", "Command response was not valid JSON.");
  }
  if (!raw || typeof raw !== "object") {
    throw workspaceError("protocol", "Command response was malformed.");
  }
  const record = raw as Record<string, unknown>;
  const envelope = (record.envelope ?? record) as Record<string, unknown>;
  if (
    typeof envelope.kid !== "string" ||
    typeof envelope.nonce !== "string" ||
    typeof envelope.sequence !== "number" ||
    typeof envelope.ciphertext !== "string"
  ) {
    throw workspaceError("protocol", "Command response envelope was malformed.");
  }
  return {
    kid: envelope.kid,
    nonce: envelope.nonce,
    sequence: envelope.sequence,
    ciphertext: envelope.ciphertext,
  };
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
