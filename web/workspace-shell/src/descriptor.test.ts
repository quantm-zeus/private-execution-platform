import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DescriptorError,
  fetchWorkspaceDescriptor,
  parseWorkspaceDescriptor,
  type WorkspaceDescriptor,
} from "./descriptor.ts";

const VALID: WorkspaceDescriptor = {
  protocol_version: 1,
  artifact_version: 1,
  artifact_kid_b64: "AAAAAAAAAAAAAAAAAAAAAA==",
  artifact_size: 1024,
  artifact_sha256_hex: "ab".repeat(32),
  package_format_version: 1,
  release_id: "release-2026-09-16",
  source_sha: "9a5a712",
  expected_public_key_fingerprint_b64: "Zm9v",
  min_shell_protocol: 1,
  max_shell_protocol: 1,
  enrolled: true,
  enrolled_kid_b64: "AAAAAAAAAAAAAAAAAAAAAA==",
  enrolled_public_key_fingerprint_b64: "Zm9v",
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("parses a complete descriptor", () => {
  const parsed = parseWorkspaceDescriptor(VALID);
  assert.equal(parsed.artifact_kid_b64, VALID.artifact_kid_b64);
  assert.equal(parsed.release_id, VALID.release_id);
  assert.equal(parsed.expected_public_key_fingerprint_b64, "Zm9v");
  assert.equal(parsed.enrolled, true);
});

test("rejects malformed descriptor shapes", () => {
  for (const bad of [
    null,
    "string",
    [],
    {},
    { ...VALID, protocol_version: "1" },
    { ...VALID, artifact_kid_b64: undefined },
    { ...VALID, min_shell_protocol: 2, max_shell_protocol: 1 },
  ]) {
    assert.throws(
      () => parseWorkspaceDescriptor(bad),
      (error: unknown) => error instanceof DescriptorError,
    );
  }
});

test("rejects a release the shell protocol cannot speak", () => {
  assert.throws(
    () => parseWorkspaceDescriptor({ ...VALID, min_shell_protocol: 2, max_shell_protocol: 3 }),
    (error: unknown) =>
      error instanceof DescriptorError && error.code === "descriptor_incompatible",
  );
  assert.throws(
    () => parseWorkspaceDescriptor({ ...VALID, min_shell_protocol: 0, max_shell_protocol: 0 }),
    (error: unknown) =>
      error instanceof DescriptorError && error.code === "descriptor_incompatible",
  );
});

test("fetch returns a validated descriptor over same-origin credentials", async () => {
  let calledUrl = "";
  let calledInit: RequestInit | undefined;
  const descriptor = await fetchWorkspaceDescriptor({
    fetchFn: (async (url: string, init?: RequestInit) => {
      calledUrl = String(url);
      calledInit = init;
      return jsonResponse(VALID);
    }) as unknown as typeof fetch,
  });
  assert.equal(calledUrl, "/internal/workspace/descriptor");
  assert.equal(calledInit?.credentials, "same-origin");
  assert.equal(descriptor.release_id, VALID.release_id);
});

test("fetch classifies unauthorized and unavailable responses", async () => {
  await assert.rejects(
    fetchWorkspaceDescriptor({
      fetchFn: (async () => jsonResponse({ code: "unauthorized" }, 401)) as unknown as typeof fetch,
    }),
    (error: unknown) =>
      error instanceof DescriptorError && error.code === "descriptor_unauthorized",
  );
  await assert.rejects(
    fetchWorkspaceDescriptor({
      fetchFn: (async () => jsonResponse({ code: "unavailable" }, 503)) as unknown as typeof fetch,
    }),
    (error: unknown) =>
      error instanceof DescriptorError && error.code === "descriptor_unavailable",
  );
  await assert.rejects(
    fetchWorkspaceDescriptor({
      fetchFn: (async () => {
        throw new TypeError("network down");
      }) as unknown as typeof fetch,
    }),
    (error: unknown) =>
      error instanceof DescriptorError && error.code === "descriptor_unavailable",
  );
});

test("fetch rejects a non-JSON or malformed body", async () => {
  await assert.rejects(
    fetchWorkspaceDescriptor({
      fetchFn: (async () =>
        new Response("not json", { status: 200 })) as unknown as typeof fetch,
    }),
    (error: unknown) =>
      error instanceof DescriptorError && error.code === "descriptor_malformed",
  );
  await assert.rejects(
    fetchWorkspaceDescriptor({
      fetchFn: (async () => jsonResponse({ protocol_version: 1 })) as unknown as typeof fetch,
    }),
    (error: unknown) =>
      error instanceof DescriptorError && error.code === "descriptor_malformed",
  );
});
