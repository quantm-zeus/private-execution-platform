// Authenticated workspace artifact/release descriptor client.
//
// The clear shell discovers the artifact Key ID and the release fingerprint
// from the server after passkey authentication, so a normal user never types a
// KID. The descriptor contains only public release metadata: version, KID,
// digests, release identity, and the recipient public-key fingerprint the
// enrolled workspace key must match.
//
// Invariants:
// - No secret material ever appears in a descriptor or an error.
// - Same-origin credentials only; the session lives in an HttpOnly cookie.
// - Fail closed: a missing/malformed/incompatible descriptor throws a typed
//   error and the caller must keep the workspace locked.

/** Wire shape returned by `GET /internal/workspace/descriptor`. */
export interface WorkspaceDescriptor {
  protocol_version: number;
  artifact_version: number;
  artifact_kid_b64: string;
  artifact_size: number;
  artifact_sha256_hex: string;
  package_format_version: number;
  release_id: string | null;
  source_sha: string | null;
  expected_public_key_fingerprint_b64: string | null;
  min_shell_protocol: number;
  max_shell_protocol: number;
  enrolled: boolean;
  enrolled_kid_b64: string | null;
  enrolled_public_key_fingerprint_b64: string | null;
}

export const WORKSPACE_PROTOCOL_VERSION = 1;
export const DEFAULT_DESCRIPTOR_URL = "/internal/workspace/descriptor";

export type DescriptorErrorCode =
  | "descriptor_unavailable"
  | "descriptor_unauthorized"
  | "descriptor_malformed"
  | "descriptor_incompatible";

export class DescriptorError extends Error {
  readonly code: DescriptorErrorCode;
  readonly status: number | undefined;

  constructor(code: DescriptorErrorCode, status?: number) {
    // Generic message: never carries release material or server text.
    super("workspace descriptor unavailable");
    this.name = "DescriptorError";
    this.code = code;
    this.status = status;
  }
}

export interface DescriptorOptions {
  url?: string;
  fetchFn?: typeof fetch;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/**
 * Parse and validate an untrusted descriptor payload. Throws
 * `DescriptorError("descriptor_malformed")` on any shape mismatch and
 * `descriptor_incompatible` when the release cannot be spoken to.
 */
export function parseWorkspaceDescriptor(input: unknown): WorkspaceDescriptor {
  if (!isRecord(input)) throw new DescriptorError("descriptor_malformed");
  const protocol = input.protocol_version;
  const artifactVersion = input.artifact_version;
  const kid = input.artifact_kid_b64;
  const packageFormat = input.package_format_version;
  const minProtocol = input.min_shell_protocol;
  const maxProtocol = input.max_shell_protocol;
  if (
    typeof protocol !== "number" ||
    typeof artifactVersion !== "number" ||
    typeof kid !== "string" ||
    typeof packageFormat !== "number" ||
    typeof minProtocol !== "number" ||
    typeof maxProtocol !== "number"
  ) {
    throw new DescriptorError("descriptor_malformed");
  }
  if (!Number.isInteger(protocol) || !Number.isInteger(artifactVersion)) {
    throw new DescriptorError("descriptor_malformed");
  }
  if (!Number.isInteger(packageFormat)) {
    throw new DescriptorError("descriptor_malformed");
  }
  if (
    !Number.isInteger(minProtocol) ||
    !Number.isInteger(maxProtocol) ||
    minProtocol > maxProtocol
  ) {
    throw new DescriptorError("descriptor_malformed");
  }
  // The artifact binding (size + digest) is authenticated server metadata; a
  // malformed value must be rejected, never silently downgraded to "skip the
  // check". The production descriptor always carries both fields.
  const artifactSize = input.artifact_size;
  if (!Number.isInteger(artifactSize) || (artifactSize as number) < 0) {
    throw new DescriptorError("descriptor_malformed");
  }
  const artifactDigest = input.artifact_sha256_hex;
  if (
    typeof artifactDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(artifactDigest)
  ) {
    throw new DescriptorError("descriptor_malformed");
  }
  if (typeof kid !== "string" || kid.length === 0) {
    throw new DescriptorError("descriptor_malformed");
  }
  const descriptor: WorkspaceDescriptor = {
    protocol_version: protocol,
    artifact_version: artifactVersion,
    artifact_kid_b64: kid,
    artifact_size: artifactSize as number,
    artifact_sha256_hex: artifactDigest,
    package_format_version: packageFormat,
    release_id: optionalString(input.release_id),
    source_sha: optionalString(input.source_sha),
    expected_public_key_fingerprint_b64: optionalString(
      input.expected_public_key_fingerprint_b64,
    ),
    min_shell_protocol: minProtocol,
    max_shell_protocol: maxProtocol,
    enrolled: input.enrolled === true,
    enrolled_kid_b64: optionalString(input.enrolled_kid_b64),
    enrolled_public_key_fingerprint_b64: optionalString(
      input.enrolled_public_key_fingerprint_b64,
    ),
  };
  if (
    WORKSPACE_PROTOCOL_VERSION < descriptor.min_shell_protocol ||
    WORKSPACE_PROTOCOL_VERSION > descriptor.max_shell_protocol
  ) {
    throw new DescriptorError("descriptor_incompatible");
  }
  return descriptor;
}

/** Fetch, validate and return the authenticated descriptor. */
export async function fetchWorkspaceDescriptor(
  options: DescriptorOptions = {},
): Promise<WorkspaceDescriptor> {
  const fetchImpl = options.fetchFn ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(options.url ?? DEFAULT_DESCRIPTOR_URL, {
      method: "GET",
      credentials: "same-origin",
      redirect: "error",
      headers: { Accept: "application/json" },
    });
  } catch {
    throw new DescriptorError("descriptor_unavailable");
  }
  if (response.status === 401 || response.status === 403) {
    throw new DescriptorError("descriptor_unauthorized", response.status);
  }
  if (!response.ok) {
    throw new DescriptorError("descriptor_unavailable", response.status);
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new DescriptorError("descriptor_malformed");
  }
  return parseWorkspaceDescriptor(body);
}
