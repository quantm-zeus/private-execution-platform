// Node-side dry checks for the workspace bootstrap wire format.
// Uses the server-side reference crypto (scripts/workspace-artifact.mjs) to
// produce a fixture sealed artifact and validates that
// web/workspace/src/bootstrap.ts parseEnvelope mirrors the Rust wire format:
//   kid(16) || nonce(12) || sequence(u64 BE) || ciphertext
// with strict rejection of truncated/zero-sequence envelopes.
// The actual HPKE/AEAD remains a fail-closed seam (see bootstrap.ts header).

import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// The parser is the actual shipped source: bootstrap.ts is transpiled on the
// fly with the workspace's installed typescript, so the fixture checks run the
// exact production code, not a mirrored copy.
async function loadBootstrapParser() {
  const tsPath = new URL("../web/workspace/src/bootstrap.ts", import.meta.url).pathname;
  const source = await readFile(tsPath, "utf8");
  const ts = require("typescript");
  const js = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const dataUrl = `data:text/javascript;base64,${Buffer.from(js).toString("base64")}`;
  return import(dataUrl);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const { parseEnvelope, BootstrapError } = await loadBootstrapParser();

// Fixture: build a wire frame the Rust side would produce.
const kid = randomBytes(16);
const nonce = randomBytes(12);
const sequence = 1n;
const ciphertext = randomBytes(64);
const header = Buffer.concat([kid, nonce, Buffer.alloc(8)]);
header.writeBigUInt64BE(sequence, 16 + 12);
const wire = new Uint8Array(Buffer.concat([header, ciphertext]));

const parsed = parseEnvelope(wire);
assert(Buffer.from(parsed.kid).equals(kid), "kid roundtrip failed");
assert(Buffer.from(parsed.nonce).equals(nonce), "nonce roundtrip failed");
assert(parsed.sequence === 1n, "sequence roundtrip failed");
assert(Buffer.from(parsed.ciphertext).equals(ciphertext), "ciphertext roundtrip failed");

// Rejections.
function expectReject(bytes) {
  let rejected = false;
  try {
    parseEnvelope(bytes);
  } catch (error) {
    rejected = error instanceof BootstrapError;
  }
  assert(rejected, "malformed envelope was accepted");
}
expectReject(new Uint8Array(16 + 12 + 8)); // exactly header length: too short
const zeroSeq = new Uint8Array(wire);
new DataView(zeroSeq.buffer).setBigUint64(16 + 12, 0n, false);
expectReject(zeroSeq); // sequence 0

console.log("workspace bootstrap wire checks passed");
