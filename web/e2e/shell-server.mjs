// Shell-unlock E2E host: serves the built cleartext shell and implements the
// `/internal/*` artifact flow against the audited `crypto-envelope` tooling:
//   - derives the workspace public key from an ephemeral unlock secret,
//   - seals the real payload build into an encrypted artifact,
//   - runs the `test-session-host` HPKE responder to wrap that artifact in a
//     transport envelope for the shell's WASM initiator.
//
// This exercises the real end-to-end unlock: authenticated in-memory artifact
// decrypt + blob instantiation of the private payload under the shell CSP.
// Nothing is written outside a temp dir and secrets never leave this process.

import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  WORKSPACE_ROOT_CONTEXT_BYTES,
  derivePublicKey,
  packDirectory,
  sealPackage,
} from "../../scripts/workspace-artifact.mjs";
import {
  RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2,
  wrapRootKey,
} from "../workspace-shell/src/recovery-wrapping.ts";

const here = fileURLToPath(new URL(".", import.meta.url));
const repoRoot = resolve(here, "../..");
const SHELL_DIST = resolve(repoRoot, "web/workspace-shell/dist");
const PAYLOAD_DIST = resolve(repoRoot, "web/workspace-payload/dist");
const PORT = Number(process.env.E2E_SHELL_PORT ?? 4320);
const CRYPTO_TARGET =
  process.env.E2E_CRYPTO_TARGET ?? process.env.CARGO_TARGET_DIR ?? resolve(repoRoot, "target");

// The workspace-artifact helpers resolve their binaries from CARGO_TARGET_DIR.
process.env.CARGO_TARGET_DIR = CRYPTO_TARGET;

const SHELL_CSP =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' blob:; style-src 'self' blob:; " +
  "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-src blob:; " +
  "worker-src 'self' blob: data:; object-src 'none'; base-uri 'none'; form-action 'self'; " +
  "frame-ancestors 'none'";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/json; charset=utf-8",
};

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req, limit = 2 * 1024 * 1024) {
  return new Promise((resolvePromise, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (chunks.length === 0) return resolvePromise({});
      try {
        resolvePromise(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new Error("invalid json"));
      }
    });
    req.on("error", reject);
  });
}

/** Line-oriented driver for the crypto-envelope test-session-host responder. */
class SessionHost {
  constructor() {
    this.child = null;
    this.buffer = "";
    this.waiters = [];
  }

  start() {
    const bin = resolve(CRYPTO_TARGET, "debug", "examples", "test-session-host");
    if (!existsSync(bin)) {
      throw new Error(
        `test-session-host not built at ${bin}; run ` +
          `CARGO_TARGET_DIR=${CRYPTO_TARGET} cargo build -p crypto-envelope --bins --example test-session-host`,
      );
    }
    this.child = spawn(bin, [], { stdio: ["pipe", "pipe", "inherit"] });
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk) => {
      this.buffer += chunk;
      let index;
      while ((index = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, index).trim();
        this.buffer = this.buffer.slice(index + 1);
        const waiter = this.waiters.shift();
        if (waiter) waiter(line);
      }
    });
  }

  /** Send a command and resolve with the next stdout line. */
  command(line) {
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => reject(new Error(`session host timeout: ${line}`)), 15_000);
      this.waiters.push((value) => {
        clearTimeout(timer);
        resolvePromise(value);
      });
      this.child.stdin.write(`${line}\n`);
    });
  }

  async offer() {
    const line = await this.command("OFFER");
    const [kidB64, pkB64] = line.split(/\s+/);
    return { kidB64, pkB64 };
  }

  async seal(encapsulatedKeyB64, inputPath, outputPath) {
    const line = await this.command(`SEAL ${encapsulatedKeyB64} ${inputPath} ${outputPath}`);
    if (line !== "OK") throw new Error(`session host seal failed: ${line}`);
  }

  stop() {
    try {
      this.child?.stdin.write("QUIT\n");
      this.child?.kill();
    } catch {
      // already gone
    }
  }
}

let ready = false;
let prepareError = null;
let secrets = null;
let sealedArtifactPath = null;
let descriptor = null;
let workspaceIdentity = null;
let recoveryWrapper = null;
let enrolledKidB64 = null;
let grant = null;
const host = new SessionHost();

// The shell reserves this credential id for the offline recovery wrapper.
const OFFLINE_RECOVERY_CREDENTIAL_B64 = Buffer.from(
  "evergreen-offline-recovery/v2",
).toString("base64");

async function prepare() {
  const secret = randomBytes(32);
  // Releases are sealed under the fixed stable workspace context, never a
  // per-release KID; the recipient identity is the stable root's public key.
  const kid = WORKSPACE_ROOT_CONTEXT_BYTES;
  const publicKey = derivePublicKey(secret, kid, 1);
  const packed = await packDirectory(PAYLOAD_DIST);
  const artifact = await sealPackage(packed, publicKey, kid, 1);
  sealedArtifactPath = join(resolve(process.env.TMPDIR ?? "/tmp"), `e2e-shell-artifact-${process.pid}.bin`);
  await writeFile(sealedArtifactPath, artifact, { mode: 0o600 });

  // Wrap the same stable root under a known offline recovery code, exactly as
  // the browser would at initial setup. The root itself never leaves this host.
  const recoveryCode = randomBytes(32).toString("base64");
  const record = await wrapRootKey(
    Buffer.from(recoveryCode, "base64"),
    secret,
    undefined,
    undefined,
    "",
    RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2,
  );
  recoveryWrapper = {
    credential_id_b64: OFFLINE_RECOVERY_CREDENTIAL_B64,
    label: "Offline recovery code",
    version: record.version,
    algorithm: record.algorithm,
    key_source: record.key_source,
    salt_b64: record.salt_b64,
    iv_b64: record.iv_b64,
    wrapped_root_key_b64: record.wrapped_root_key_b64,
    created_at_ms: Date.now(),
    last_used_at_ms: null,
    revoked_at_ms: null,
  };

  const fingerprintB64 = createHash("sha256").update(publicKey).digest("base64");
  workspaceIdentity = {
    configured: true,
    version: 1,
    public_key_b64: publicKey.toString("base64"),
    fingerprint_b64: fingerprintB64,
  };
  descriptor = {
    protocol_version: 1,
    artifact_version: 1,
    artifact_kid_b64: Buffer.from(kid).toString("base64"),
    artifact_size: artifact.length,
    artifact_sha256_hex: createHash("sha256").update(artifact).digest("hex"),
    package_format_version: 1,
    release_id: "e2e-release",
    source_sha: "e2e",
    expected_public_key_fingerprint_b64: fingerprintB64,
    min_shell_protocol: 1,
    max_shell_protocol: 1,
    enrolled: false,
    enrolled_kid_b64: null,
    enrolled_public_key_fingerprint_b64: null,
  };
  secrets = { recoveryCode, fingerprintB64 };
  host.start();
  ready = true;
}

async function serveStatic(req, res) {
  const url = new URL(req.url ?? "/", "http://localhost");
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === "/" || pathname === "") pathname = "/index.html";
  const relative = normalize(pathname).replace(/^([/\\])+/, "");
  const target = resolve(SHELL_DIST, relative);
  if (target !== SHELL_DIST && !target.startsWith(SHELL_DIST + sep)) {
    res.writeHead(403).end("forbidden");
    return;
  }
  try {
    const data = await readFile(target);
    res.writeHead(200, {
      "Content-Type": MIME[extname(target)] ?? "application/octet-stream",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": SHELL_CSP,
    });
    res.end(data);
  } catch {
    res.writeHead(404).end("not found");
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  try {
    if (path === "/__test__/unlock" && req.method === "GET") {
      if (prepareError) {
        return json(res, 200, { available: false, reason: prepareError.message });
      }
      if (!ready) return json(res, 503, { error: "not ready" });
      return json(res, 200, {
        available: true,
        ...secrets,
        artifactBytes: (await readFile(sealedArtifactPath)).length,
      });
    }

    // Same-origin axe bundle so the clear-shell security gateway can be audited
    // at moderate-or-worse, not only the encrypted payload.
    if (path === "/__test__/axe.min.js" && req.method === "GET") {
      const data = await readFile(resolve(here, "node_modules/axe-core/axe.min.js"));
      res.writeHead(200, {
        "Content-Type": "text/javascript; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Length": data.length,
      });
      res.end(data);
      return;
    }

    if (path === "/internal/auth/enrollment-status" && req.method === "GET") {
      return json(res, 200, { enrollment_open: false });
    }

    if (path === "/internal/auth/session" && req.method === "GET") {
      // The E2E host models an already-established operator session so the
      // unlock boundary can be exercised without a virtual authenticator.
      // WebAuthn itself is covered by the private-api Rust tests.
      res.writeHead(204, { "Cache-Control": "no-store" });
      res.end();
      return;
    }

    if (path === "/internal/workspace/descriptor" && req.method === "GET") {
      if (!ready || !descriptor) return json(res, 503, { error: "not ready" });
      if (enrolledKidB64) {
        return json(res, 200, {
          ...descriptor,
          enrolled: true,
          enrolled_kid_b64: enrolledKidB64,
          enrolled_public_key_fingerprint_b64:
            descriptor.expected_public_key_fingerprint_b64,
        });
      }
      return json(res, 200, descriptor);
    }

    if (path === "/internal/auth/enroll" && req.method === "POST") {
      const body = await readBody(req);
      if (typeof body.public_key !== "string" || typeof body.kid !== "string") {
        return json(res, 400, { error: "malformed enrollment" });
      }
      // Model the real server: an identical binding is idempotent, a different
      // binding for the same session conflicts.
      if (enrolledKidB64 !== null && enrolledKidB64 !== body.kid) {
        return json(res, 409, { code: "enrollment_conflict" });
      }
      enrolledKidB64 = body.kid;
      return json(res, 200, { ok: true });
    }

    if (path === "/internal/artifact/grant" && req.method === "POST") {
      const offer = await host.offer();
      grant = { grantId: randomUUID(), kid: offer.kidB64, publicKey: offer.pkB64 };
      return json(res, 200, {
        grant_id: grant.grantId,
        kid: grant.kid,
        recipient_public_key: grant.publicKey,
      });
    }

    if (path === "/internal/artifact" && req.method === "POST") {
      const body = await readBody(req);
      if (!grant || body.grant_id !== grant.grantId || body.kid !== grant.kid) {
        return json(res, 400, { error: "unknown grant" });
      }
      if (typeof body.encapsulated_key !== "string") {
        return json(res, 400, { error: "missing encapsulated key" });
      }
      const outPath = join(
        resolve(process.env.TMPDIR ?? "/tmp"),
        `e2e-shell-wire-${process.pid}.bin`,
      );
      await host.seal(body.encapsulated_key, sealedArtifactPath, outPath);
      const wire = await readFile(outPath);
      await rm(outPath, { force: true });
      res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Cache-Control": "no-store",
        "Content-Length": wire.length,
      });
      res.end(wire);
      return;
    }

    if (path === "/internal/workspace/identity" && req.method === "GET") {
      if (!ready || !workspaceIdentity) return json(res, 503, { error: "not ready" });
      return json(res, 200, workspaceIdentity);
    }

    if (path === "/internal/workspace/recovery" && req.method === "GET") {
      if (!ready || !recoveryWrapper) return json(res, 503, { error: "not ready" });
      return json(res, 200, { wrappers: [recoveryWrapper] });
    }

    // Wrapper mutation requires proof of possession; this minimal host does not
    // implement it, so it stays closed rather than pretending to accept a write.
    if (path.startsWith("/internal/workspace/recovery")) {
      return json(res, 503, { code: "recovery_unavailable" });
    }

    if (path.startsWith("/internal/") || path.startsWith("/v1/")) {
      return json(res, 404, { error: "not found" });
    }

    await serveStatic(req, res);
  } catch (error) {
    json(res, 500, { error: error instanceof Error ? error.message : "error" });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  // eslint-disable-next-line no-console
  console.log(`e2e shell unlock host on http://127.0.0.1:${PORT}`);
});

async function shutdown() {
  host.stop();
  if (sealedArtifactPath) await rm(sealedArtifactPath, { force: true }).catch(() => {});
  server.close();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

prepare().catch((error) => {
  prepareError = error instanceof Error ? error : new Error(String(error));
  // Keep serving so the E2E can report an explicit skip reason.
  console.error(`shell-unlock host not ready: ${prepareError.message}`);
});
