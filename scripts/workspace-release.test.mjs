import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import {
  chmod,
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  readlink,
  rename,
  rm,
  stat,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { writeArtifactAtomically } from "./build-workspace-encrypted.mjs";
import { sanitizeConsoleSource } from "./build-crypto-wasm-bindings.mjs";
import {
  ARTIFACT_VERSION,
  KID_BYTES,
  WORKSPACE_ROOT_CONTEXT_B64,
  WORKSPACE_ROOT_CONTEXT_BYTES,
  artifactKidFromEnv,
  decryptArtifact,
  derivePublicKey,
  sealPackage,
} from "./workspace-artifact.mjs";
import {
  ARTIFACT_FILE,
  CURRENT_LINK,
  DEFAULT_PAYLOAD_DIR,
  MANIFEST_FILE,
  PREVIOUS_LINK,
  RELEASE_LOCK_DIR,
  RELEASE_LOCK_OWNER_FILE,
  ReleaseLockTimeoutError,
  SHELL_DIR,
  acquireReleaseLock,
  buildAndPublishRelease,
  computeReleaseManifest,
  digestDirectory,
  isDefaultPayloadDir,
  publishRelease,
  readRelease,
  releaseIdFor,
  releaseReleaseLock,
  rollbackCurrent,
  switchCurrent,
  sweepStaleStaging,
  validateReleaseManifest,
  withReleaseLock,
  writeShellCacheHeaders,
} from "./workspace-release.mjs";

const PUBLIC_KEY_B64 = Buffer.alloc(32, 7).toString("base64");
// Releases are sealed under the fixed stable workspace context, never a
// per-release KID.
const KID = Buffer.from(WORKSPACE_ROOT_CONTEXT_B64, "base64");
const KID_B64 = KID.toString("base64");

const IS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;

// The real shipped shell headers. Assertions must accept production verbatim
// (including its full-strength CSP), never a shortened stand-in.
const PRODUCTION_HEADERS_PATH = fileURLToPath(
  new URL("../web/workspace-shell/public/_headers", import.meta.url),
);
const PRODUCTION_HEADERS = await readFile(PRODUCTION_HEADERS_PATH, "utf8");
const PRODUCTION_CSP = (() => {
  const match = /^\s*Content-Security-Policy:\s*(.+)$/im.exec(PRODUCTION_HEADERS);
  assert.ok(match, "production _headers must declare a Content-Security-Policy");
  return match[1].trim();
})();
const PARTIAL_HEADERS = ["/index.html", "  Cache-Control: no-store", ""].join("\n");

/**
 * Resolve `_headers`-style rules the way Cloudflare Pages does: every matching
 * rule is inherited and a header present in more than one matching rule is
 * comma-joined. Mirrors the boundary verifier, so a regression that
 * reintroduces a wildcard Cache-Control fails here too.
 */
function resolveHeaderRules(text, requestPath) {
  const rules = [];
  let current = null;
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.replace(/\s+$/, "");
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    if (/^\s/.test(line)) {
      const match = /^\s+([A-Za-z0-9-]+)\s*:\s*(.*)$/.exec(line);
      if (current && match) {
        const name = match[1].toLowerCase();
        const value = match[2].trim();
        current.headers[name] =
          current.headers[name] === undefined ? value : `${current.headers[name]}, ${value}`;
      }
      continue;
    }
    current = { path: trimmed, headers: {} };
    rules.push(current);
  }
  const matches = (pattern, path) => {
    if (!pattern.includes("*")) return pattern === path;
    const star = pattern.indexOf("*");
    const prefix = pattern.slice(0, star);
    const suffix = pattern.slice(star + 1);
    return path.startsWith(prefix) && path.endsWith(suffix) && path.length >= prefix.length + suffix.length;
  };
  const resolved = {};
  for (const rule of rules) {
    if (!matches(rule.path, requestPath)) continue;
    for (const [name, value] of Object.entries(rule.headers)) {
      resolved[name] = resolved[name] === undefined ? value : `${resolved[name]}, ${value}`;
    }
  }
  return resolved;
}

/** Fail fast instead of hanging when a lock regression deadlocks a test. */
function withTimeout(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`timed out: ${label}`)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

/** A pid that is guaranteed to be dead: a child we spawned and reaped. */
async function spawnDeadPid() {
  const child = spawn(process.execPath, ["-e", ""], { stdio: "ignore" });
  const pid = child.pid;
  await once(child, "exit");
  return pid;
}

/** Plant a pre-existing lock directory with the given owner stamp. */
async function plantLock(root, owner) {
  const lockPath = join(root, RELEASE_LOCK_DIR);
  await mkdir(lockPath);
  await writeFile(join(lockPath, RELEASE_LOCK_OWNER_FILE), `${JSON.stringify(owner)}\n`);
  return lockPath;
}

function fakeArtifact() {
  // version(1) || kid(16) || encapped(32) || ciphertext tag(16)
  return Buffer.concat([Buffer.from([1]), KID, Buffer.alloc(32, 9), Buffer.alloc(16, 4)]);
}

function manifestFor(artifact, overrides = {}) {
  return {
    ...computeReleaseManifest({
      releaseId: "release-abc",
      sourceSha: "9a5a712",
      artifact,
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      shellAssetDigest: createHash("sha256").update("shell").digest("hex"),
    }),
    ...overrides,
  };
}

test("manifest roundtrips and is bound to exact artifact bytes", () => {
  const artifact = fakeArtifact();
  const manifest = manifestFor(artifact);
  validateReleaseManifest(manifest, artifact);
  assert.equal(manifest.artifact.sha256_hex, createHash("sha256").update(artifact).digest("hex"));
  assert.equal(manifest.artifact.size, artifact.length);
  assert.equal(manifest.artifact.kid_b64, KID_B64);
  assert.equal(manifest.manifest_version, 1);
});

test("console neutralization is valid JS for zero- and multi-arg calls", () => {
  const source = [
    'console.warn("wasm failed", e);',
    "console.groupEnd();",
    'console["warn"]("bracket", e);',
    "const x = 1;",
  ].join("\n");
  const stripped = sanitizeConsoleSource(source);
  assert.ok(!/\bconsole\b/.test(stripped), "no console identifier remains");
  assert.ok(stripped.includes('(()=>{})("wasm failed", e)'));
  assert.ok(stripped.includes("(()=>{})()"), "zero-arg call neutralized");
  assert.ok(stripped.includes('(()=>{})("bracket", e)'), "computed-bracket call neutralized");
  // The transform must never emit syntactically invalid JS (the old `void (`
  // replacement turned `console.groupEnd()` into the invalid `void ();`).
  assert.doesNotThrow(() => new Function(stripped));
  // A form the transform does not understand is refused, not shipped.
  assert.throws(() => sanitizeConsoleSource("const c = console;"), /console usage remains/);
});

test("manifest validation rejects every mismatch", () => {
  const artifact = fakeArtifact();
  const manifest = manifestFor(artifact);
  validateReleaseManifest(manifest, artifact);

  assert.throws(() =>
    validateReleaseManifest({ ...manifest, manifest_version: 2 }, artifact),
  );
  assert.throws(() => validateReleaseManifest(manifest, Buffer.concat([artifact, Buffer.from([0])])));
  assert.throws(() =>
    validateReleaseManifest(
      { ...manifest, artifact: { ...manifest.artifact, sha256_hex: "00".repeat(32) } },
      artifact,
    ),
  );
  assert.throws(() =>
    validateReleaseManifest(
      { ...manifest, artifact: { ...manifest.artifact, size: artifact.length + 1 } },
      artifact,
    ),
  );
  assert.throws(() =>
    validateReleaseManifest(
      { ...manifest, artifact: { ...manifest.artifact, kid_b64: Buffer.alloc(16, 1).toString("base64") } },
      artifact,
    ),
  );
  assert.throws(() =>
    validateReleaseManifest(
      { ...manifest, workspace_protocol: { min: 2, max: 3 } },
      artifact,
    ),
  );
  // Non-integer protocol fields must not slip through relational comparisons.
  assert.throws(() =>
    validateReleaseManifest(
      { ...manifest, workspace_protocol: { min: {}, max: {} } },
      artifact,
    ),
  );
  assert.throws(() =>
    validateReleaseManifest(
      { ...manifest, workspace_protocol: { min: 0, max: 300 } },
      artifact,
    ),
  );
  assert.throws(() =>
    validateReleaseManifest(
      { ...manifest, recipient: { public_key_fingerprint_b64: "AAAA" } },
      artifact,
    ),
  );
});

test("release ids are deterministic and stable", () => {
  const digest = "abcdef0123456789".repeat(4);
  // Exact expected id, not a self-comparison: source sha is lowered and cut to
  // 12 hex chars, and the artifact digest contributes its first 12.
  assert.equal(releaseIdFor("9a5a712deadbeef", digest), "9a5a712deadb-abcdef012345");
  assert.notEqual(releaseIdFor("9a5a712", digest), releaseIdFor("beef123", digest));
  assert.notEqual(
    releaseIdFor("9a5a712", digest),
    releaseIdFor("9a5a712", "ffffffffffffffff".repeat(4)),
  );
  assert.match(releaseIdFor("9a5a712", digest), /^9a5a712-[0-9a-f]{12}$/);
});

test("directory digest changes with content and is path sensitive", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-digest-"));
  try {
    await mkdir(join(root, "assets"));
    await writeFile(join(root, "index.html"), "a");
    await writeFile(join(root, "assets", "app.js"), "b");
    const first = await digestDirectory(root);
    // Baseline: hashing the unchanged tree is stable.
    assert.equal(await digestDirectory(root), first);
    // Identical bytes at a different path must change the digest.
    await rename(join(root, "assets", "app.js"), join(root, "assets", "renamed.js"));
    const renamed = await digestDirectory(root);
    assert.notEqual(first, renamed);
    // Restoring the original path must reproduce the original digest exactly.
    await rename(join(root, "assets", "renamed.js"), join(root, "assets", "app.js"));
    assert.equal(await digestDirectory(root), first);
    // Adding a path must also change the digest.
    await writeFile(join(root, "assets", "extra.js"), "");
    const added = await digestDirectory(root);
    assert.notEqual(added, first);
    // A content change at the same path changes the digest.
    await writeFile(join(root, "assets", "app.js"), "c");
    const changed = await digestDirectory(root);
    assert.notEqual(changed, added);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("shell cache headers accept the shipped production _headers verbatim", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-"));
  try {
    await writeFile(join(root, "_headers"), PRODUCTION_HEADERS);
    await writeShellCacheHeaders(root);
    const headers = await readFile(join(root, "_headers"), "utf8");
    // The production CSP must survive byte-for-byte: the writer must accept the
    // real shipped policy, not merely a shortened stand-in.
    assert.ok(
      headers.includes(`Content-Security-Policy: ${PRODUCTION_CSP}`),
      "production CSP must be accepted and retained verbatim",
    );
    assert.match(headers, /X-Content-Type-Options: nosniff/);
    assert.match(headers, /X-Frame-Options: DENY/);
    assert.match(headers, /Referrer-Policy: no-referrer/);
    // Cache rules are appended, not substituted for the security block.
    assert.ok(headers.includes("/index.html\n  Cache-Control: no-store, must-revalidate"));
    assert.ok(headers.includes("/\n  Cache-Control: no-store, must-revalidate"));
    assert.ok(
      headers.includes("/assets/*\n  Cache-Control: public, max-age=31536000, immutable"),
    );
    // The `/*` rule must precede the more specific overrides.
    assert.ok(headers.indexOf("/*") < headers.indexOf("/index.html"));
    // The wildcard must not carry Cache-Control: Cloudflare Pages joins every
    // matching rule, so `no-store` on `/*` would defeat the `/assets/*`
    // immutable value.
    const wildcardBlock = headers
      .split("\n\n")
      .find((block) => block.split("\n")[0].trim() === "/*");
    assert.ok(wildcardBlock, "wildcard block present");
    assert.equal(/^\s*Cache-Control\s*:/im.test(wildcardBlock), false);
    // Re-running is idempotent: no duplicated cache rules.
    await writeShellCacheHeaders(root);
    const rerun = await readFile(join(root, "_headers"), "utf8");
    assert.equal(rerun, headers);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("published cache policy never joins no-store onto hashed assets", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-join-"));
  try {
    await writeFile(join(root, "_headers"), PRODUCTION_HEADERS);
    await writeShellCacheHeaders(root);
    const headers = await readFile(join(root, "_headers"), "utf8");
    // Cloudflare Pages inherits every matching rule and comma-joins duplicates.
    // The HTML entrypoint must be no-store and must not inherit `immutable`; a
    // hashed asset must be immutable and must not inherit `no-store`.
    const html = String(resolveHeaderRules(headers, "/index.html")["cache-control"] ?? "").toLowerCase();
    assert.match(html, /no-store/);
    assert.doesNotMatch(html, /immutable/);
    const asset = String(
      resolveHeaderRules(headers, "/assets/app-abc123.js")["cache-control"] ?? "",
    ).toLowerCase();
    assert.match(asset, /immutable/);
    assert.doesNotMatch(asset, /no-store/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a wildcard Cache-Control is refused (it would defeat immutable assets)", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-wildcard-cache-"));
  try {
    const withWildcardCache = PRODUCTION_HEADERS.replace(
      "/*\n",
      "/*\n  Cache-Control: no-store\n",
    );
    assert.notEqual(withWildcardCache, PRODUCTION_HEADERS, "fixture must add a wildcard Cache-Control");
    await writeFile(join(root, "_headers"), withWildcardCache);
    await assert.rejects(writeShellCacheHeaders(root), /must not set Cache-Control/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a path-specific rule cannot weaken a hardened security header", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-specific-"));
  try {
    const weakened = `${PRODUCTION_HEADERS.trimEnd()}\n\n/index.html\n  Content-Security-Policy: default-src *\n`;
    await writeFile(join(root, "_headers"), weakened);
    await assert.rejects(
      writeShellCacheHeaders(root),
      /weakens hardened content-security-policy/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a Cloudflare header detach directive is refused", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-detach-"));
  try {
    // `! Header-Name` detaches an inherited header on Cloudflare Pages. A
    // parser that only understands `Name: value` would ignore these lines and
    // let `/index.html` drop X-Frame-Options and CSP from the recovery page.
    const detached = `${PRODUCTION_HEADERS.trimEnd()}\n\n/index.html\n  ! X-Frame-Options\n  ! Content-Security-Policy\n`;
    await writeFile(join(root, "_headers"), detached);
    await assert.rejects(writeShellCacheHeaders(root), /must not detach a header/);
    // A lone CR is a line boundary on hosts whose config parser uses
    // `splitlines()`; splitting only on `\n` would let
    // `/index.html\r  ! X-Frame-Options` through.
    const carriageReturn = `${PRODUCTION_HEADERS.trimEnd()}\n\n/index.html\r  ! X-Frame-Options\n`;
    await writeFile(join(root, "_headers"), carriageReturn);
    await assert.rejects(writeShellCacheHeaders(root), /must not detach a header/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("shell cache headers synthesize the complete hardened block when none shipped", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-synth-"));
  try {
    await writeShellCacheHeaders(root);
    const headers = await readFile(join(root, "_headers"), "utf8");
    assert.match(headers, /^\/\*/m);
    // The synthesized block must carry the full hardened header set, not just
    // Cache-Control, and its CSP must equal the real shipped policy exactly.
    assert.match(headers, /Cache-Control: no-store/);
    assert.match(headers, /X-Content-Type-Options: nosniff/);
    assert.match(headers, /X-Frame-Options: DENY/);
    assert.match(headers, /Referrer-Policy: no-referrer/);
    assert.ok(headers.includes(`Content-Security-Policy: ${PRODUCTION_CSP}`));
    assert.ok(headers.includes("/index.html\n  Cache-Control: no-store, must-revalidate"));
    assert.ok(headers.includes("/\n  Cache-Control: no-store, must-revalidate"));
    assert.ok(
      headers.includes("/assets/*\n  Cache-Control: public, max-age=31536000, immutable"),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("shell cache headers refuse an existing _headers without the hardened /* rule", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-refuse-"));
  try {
    // Only a specific rule, no hardened wildcard: fail closed instead of
    // appending cache rules to a shell that would lose its security headers.
    await writeFile(join(root, "_headers"), PARTIAL_HEADERS);
    await assert.rejects(writeShellCacheHeaders(root), /hardened \/\* rule/);
    // A wildcard that is missing a hardened header is refused too.
    await writeFile(
      join(root, "_headers"),
      [
        "/*",
        "  Cache-Control: no-store",
        "  X-Content-Type-Options: nosniff",
        "  X-Frame-Options: DENY",
        "  Referrer-Policy: no-referrer",
        "",
      ].join("\n"),
    );
    await assert.rejects(writeShellCacheHeaders(root), /missing hardened content-security-policy/);
    // An empty file is not a hardened shell either.
    await writeFile(join(root, "_headers"), "");
    await assert.rejects(writeShellCacheHeaders(root), /hardened \/\* rule/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a second weaker /* rule cannot bypass the hardened header guard", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-dup-"));
  try {
    // First wildcard is hardened, second is weaker: checking only the first
    // would let the weaker rule survive and un-harden the shell depending on
    // host evaluation order.
    await writeFile(
      join(root, "_headers"),
      `${PRODUCTION_HEADERS.trimEnd()}\n\n/*\n  Cache-Control: no-store\n`,
    );
    await assert.rejects(
      writeShellCacheHeaders(root),
      /missing hardened x-content-type-options/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a weakened or extended CSP is rejected", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-csp-"));
  try {
    const weakened = PRODUCTION_HEADERS.replace(
      `Content-Security-Policy: ${PRODUCTION_CSP}`,
      "Content-Security-Policy: default-src *",
    );
    assert.notEqual(weakened, PRODUCTION_HEADERS, "fixture must actually rewrite the CSP");
    await writeFile(join(root, "_headers"), weakened);
    await assert.rejects(
      writeShellCacheHeaders(root),
      /missing hardened content-security-policy/,
    );

    // A CSP that merely contains the hardened directives plus an extra source
    // must not be accepted either: the required value is exact.
    const extended = PRODUCTION_HEADERS.replace(
      `Content-Security-Policy: ${PRODUCTION_CSP}`,
      `Content-Security-Policy: ${PRODUCTION_CSP} script-src-elem *`,
    );
    await writeFile(join(root, "_headers"), extended);
    await assert.rejects(
      writeShellCacheHeaders(root),
      /missing hardened content-security-policy/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a comment line cannot detach following headers from the /* rule", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-comment-"));
  try {
    // A column-0 comment between header lines used to become its own path rule,
    // stealing every header after it away from `/*`.
    const withComment = PRODUCTION_HEADERS.replace(
      "  X-Content-Type-Options: nosniff\n",
      "  X-Content-Type-Options: nosniff\n# operator note\n",
    );
    assert.notEqual(withComment, PRODUCTION_HEADERS, "fixture must inject a comment");
    await writeFile(join(root, "_headers"), withComment);
    await writeShellCacheHeaders(root);
    const headers = await readFile(join(root, "_headers"), "utf8");
    assert.ok(
      headers.includes(`Content-Security-Policy: ${PRODUCTION_CSP}`),
      "headers after the comment must stay attached to the /* rule",
    );
    // The comment itself is preserved.
    assert.ok(headers.includes("# operator note"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("managed-path blocks keep unrelated headers while cache rules are replaced", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-preserve-"));
  try {
    // A managed path carrying HSTS: only its Cache-Control line may be dropped.
    await writeFile(
      join(root, "_headers"),
      [
        PRODUCTION_HEADERS.trimEnd(),
        "",
        "/index.html",
        "  Cache-Control: no-store, must-revalidate",
        "  Strict-Transport-Security: max-age=63072000",
        "",
      ].join("\n"),
    );
    await writeShellCacheHeaders(root);
    const headers = await readFile(join(root, "_headers"), "utf8");
    assert.ok(
      headers.includes("Strict-Transport-Security: max-age=63072000"),
      "HSTS must not be dropped with the cache block",
    );
    const indexBlocks = headers
      .split("\n\n")
      .filter((block) => block.split("\n")[0].trim() === "/index.html");
    assert.equal(
      indexBlocks.length,
      2,
      "preserved header block plus the canonical cache rule",
    );
    assert.ok(indexBlocks.some((block) => block.includes("Strict-Transport-Security")));
    assert.ok(indexBlocks.some((block) => block.includes("must-revalidate")));
    // No stale cache-control duplicated into the preserved block.
    assert.equal(indexBlocks[0].includes("Cache-Control"), false);
    // Re-running is idempotent.
    await writeShellCacheHeaders(root);
    const rerun = await readFile(join(root, "_headers"), "utf8");
    assert.equal(rerun, headers);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rollback refuses with no previous and when current === previous", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-rollback-guard-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-rollback-guard-src-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    const { releaseId } = await publishRelease({
      releasesRoot: root,
      artifact: fakeArtifact(),
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });
    // Only a current release exists: nothing to roll back to.
    await assert.rejects(rollbackCurrent(root), /no previous release/);
    // Simulate the crash window: previous points at the same release as
    // current. Rolling back would be a silent no-op and must be refused.
    await symlink(releaseId, join(root, PREVIOUS_LINK));
    await assert.rejects(rollbackCurrent(root), /same release/);
    // The refusal must not have mutated either link.
    assert.equal(await readlink(join(root, CURRENT_LINK)), releaseId);
    assert.equal(await readlink(join(root, PREVIOUS_LINK)), releaseId);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("publish, switch and rollback are atomic and immutable", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-publish-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-shell-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    await mkdir(join(shellDir, "assets"));
    await writeFile(join(shellDir, "assets", "index-abc.js"), "console.log(1)");
    const artifact = fakeArtifact();

    const first = await publishRelease({
      releasesRoot: root,
      artifact,
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });
    assert.equal(await readlink(join(root, CURRENT_LINK)), first.releaseId);

    // Republishing identical bytes is idempotent: the release id is a content
    // address, so re-running publication must not fail (or rewrite the dir).
    const again = await publishRelease({
      releasesRoot: root,
      artifact,
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });
    assert.equal(again.releaseId, first.releaseId);
    assert.equal(await readlink(join(root, CURRENT_LINK)), first.releaseId);

    // Publish a second, different release and switch.
    const secondArtifact = Buffer.concat([Buffer.from([1]), KID, Buffer.alloc(32, 5), Buffer.alloc(16, 6)]);
    // Release id derives from the source sha; use a different source sha.
    const second = await publishRelease({
      releasesRoot: root,
      artifact: secondArtifact,
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "beef123",
      shellDir,
    });
    assert.notEqual(second.releaseId, first.releaseId);
    assert.equal(await readlink(join(root, CURRENT_LINK)), second.releaseId);
    assert.equal(await readlink(join(root, PREVIOUS_LINK)), first.releaseId);

    const rolled = await rollbackCurrent(root);
    assert.equal(rolled.to, first.releaseId);
    assert.equal(await readlink(join(root, CURRENT_LINK)), first.releaseId);
    assert.equal(await readlink(join(root, PREVIOUS_LINK)), second.releaseId);

    // readRelease validates the exact bytes on disk.
    const { manifest, artifact: onDisk } = await readRelease(root, first.releaseId);
    assert.equal(manifest.release_id, first.releaseId);
    assert.deepEqual(onDisk, artifact);
    const releaseManifest = JSON.parse(
      await readFile(join(root, first.releaseId, MANIFEST_FILE), "utf8"),
    );
    assert.equal(releaseManifest.release_id, first.releaseId);
    assert.ok(await readFile(join(root, first.releaseId, ARTIFACT_FILE)));
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("a release that cannot acquire the lock leaves no staging directory behind", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-staging-leak-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-staging-leak-src-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    // A live lock owned by this process is never evicted, so a tiny lock budget
    // makes `withReleaseLock` reject before its callback ever runs. The staging
    // directory is created before acquisition, so only the outer guard can
    // remove it.
    await plantLock(root, {
      pid: process.pid,
      token: "live-holder",
      startedAtMs: Date.now(),
    });
    await assert.rejects(
      publishRelease({
        releasesRoot: root,
        artifact: fakeArtifact(),
        publicKeyB64: PUBLIC_KEY_B64,
        kidB64: KID_B64,
        sourceSha: "9a5a712",
        shellDir,
        lockTimeoutMs: 120,
        lockStaleMs: 1,
      }),
      ReleaseLockTimeoutError,
    );
    const leftovers = (await readdir(root)).filter((name) => name.startsWith(".staging-"));
    assert.deepEqual(leftovers, [], "a failed lock acquisition must not leak staging");
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("a world-writable release artifact is refused before switching", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-mode-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-mode-src-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    const { releaseId } = await publishRelease({
      releasesRoot: root,
      artifact: fakeArtifact(),
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });
    // The private-api hardened loader refuses a group/world-writable trust file,
    // so publication must refuse to switch `current` to one.
    await chmod(join(root, releaseId, ARTIFACT_FILE), 0o666);
    await assert.rejects(readRelease(root, releaseId), /group\/world writable/);
    await assert.rejects(switchCurrent(root, releaseId), /group\/world writable/);
    // A world-writable release directory is refused too.
    await chmod(join(root, releaseId, ARTIFACT_FILE), 0o600);
    await chmod(join(root, releaseId), 0o777);
    await assert.rejects(readRelease(root, releaseId), /group\/world writable/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("switching to an unpublished release refuses", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-switch-"));
  try {
    // A non-canonical id fails the shape check before any disk access.
    await assert.rejects(switchCurrent(root, "missing-release"), /invalid release id/);
    // A canonical-but-absent id reaches the read and fails closed with ENOENT,
    // distinctly from the shape rejection above.
    await assert.rejects(
      switchCurrent(root, "abcdef012345-abcdef012345"),
      (error) => error?.code === "ENOENT",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a tampered current link is never persisted as previous", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-current-tamper-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-current-tamper-src-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    const { releaseId } = await publishRelease({
      releasesRoot: root,
      artifact: fakeArtifact(),
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });
    // `current` is attacker-influencable link content and a switch writes it to
    // `previous`. A tampered target must be rejected by the id check, never
    // persisted as a rollback destination.
    await rm(join(root, CURRENT_LINK), { force: true });
    await symlink("../../etc", join(root, CURRENT_LINK));
    await assert.rejects(switchCurrent(root, releaseId), /invalid release id/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("a corrupt existing release never leaks the staging directory", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-staging-leak-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-staging-src-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    const artifact = fakeArtifact();
    const { releaseId } = await publishRelease({
      releasesRoot: root,
      artifact,
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });
    // Corrupt the published shell so the re-publish path throws while reading
    // the existing release, after staging has already been written.
    await writeFile(join(root, releaseId, SHELL_DIR, "index.html"), "tampered");
    await assert.rejects(
      publishRelease({
        releasesRoot: root,
        artifact,
        publicKeyB64: PUBLIC_KEY_B64,
        kidB64: KID_B64,
        sourceSha: "9a5a712",
        shellDir,
      }),
      /shell asset digest mismatch/,
    );
    const entries = await readdir(root);
    assert.deepEqual(
      entries.filter((name) => name.startsWith(".staging-")),
      [],
      "staging directory leaked on the existing-release error path",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("a tampered shell tree fails release validation", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-shell-tamper-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-shell-src-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    await mkdir(join(shellDir, "assets"));
    await writeFile(join(shellDir, "assets", "index-abc.js"), "console.log(1)");
    const { releaseId } = await publishRelease({
      releasesRoot: root,
      artifact: fakeArtifact(),
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });
    // A clean release validates, including the shell digest.
    await readRelease(root, releaseId);

    await writeFile(join(root, releaseId, SHELL_DIR, "index.html"), "tampered");
    await assert.rejects(readRelease(root, releaseId), /shell asset digest mismatch/);
    // The tampered release is also refused by an atomic switch.
    await assert.rejects(switchCurrent(root, releaseId), /shell asset digest mismatch/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("release ids cannot escape the releases root", () => {
  const digest = "abcdef0123456789".repeat(4);
  for (const raw of ["../../etc/ev", "..\\..\\weird", "a/b/c", "9A5A712"]) {
    const id = releaseIdFor(raw, digest);
    assert.match(id, /^[0-9a-f]+-[0-9a-f]{12}$/);
    assert.ok(!id.includes("..") && !id.includes("/") && !id.includes("\\"));
  }
  assert.throws(() => releaseIdFor("", digest), /hex/);
  assert.throws(() => releaseIdFor("!!!!", digest), /hex/);
});

test("a shell-only change under the same release id is refused", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-shell-change-"));
  const shellA = await mkdtemp(join(tmpdir(), "release-shell-a-"));
  const shellB = await mkdtemp(join(tmpdir(), "release-shell-b-"));
  try {
    await writeFile(join(shellA, "index.html"), "<!doctype html>a");
    await publishRelease({
      releasesRoot: root,
      artifact: fakeArtifact(),
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir: shellA,
    });
    // Same artifact and source SHA => same content-addressed release id, but a
    // different shell must not be silently published over the existing release.
    await writeFile(join(shellB, "index.html"), "<!doctype html>b");
    await assert.rejects(
      publishRelease({
        releasesRoot: root,
        artifact: fakeArtifact(),
        publicKeyB64: PUBLIC_KEY_B64,
        kidB64: KID_B64,
        sourceSha: "9a5a712",
        shellDir: shellB,
      }),
      /immutable/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellA, { recursive: true, force: true });
    await rm(shellB, { recursive: true, force: true });
  }
});

test("read/switch reject a release id that is not a single directory name", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-traversal-"));
  try {
    for (const bad of ["../../etc/passwd", "../x", "a/b", "9A5A712-abcdef012345", ".", ""]) {
      await assert.rejects(readRelease(root, bad), /invalid release id/);
      await assert.rejects(switchCurrent(root, bad), /invalid release id/);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a manifest that disagrees with its directory is refused", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-mismatch-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-mismatch-src-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    const { releaseId } = await publishRelease({
      releasesRoot: root,
      artifact: fakeArtifact(),
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });
    const manifestPath = join(root, releaseId, MANIFEST_FILE);
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.release_id = "deadbeefde-000000000000";
    await writeFile(manifestPath, JSON.stringify(manifest));
    await assert.rejects(readRelease(root, releaseId), /does not match its directory/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("validateReleaseManifest rejects missing manifest blocks without a TypeError", () => {
  const artifact = fakeArtifact();
  const manifest = manifestFor(artifact);
  assert.throws(
    () => validateReleaseManifest({ ...manifest, artifact: undefined }, artifact),
    /artifact missing/,
  );
  assert.throws(
    () => validateReleaseManifest({ ...manifest, recipient: undefined }, artifact),
    /recipient missing/,
  );
  assert.throws(
    () => validateReleaseManifest({ ...manifest, workspace_protocol: undefined }, artifact),
    /protocol missing/,
  );
});

test("a symlinked release directory or shell is refused", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-symlink-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-symlink-src-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    const { releaseId } = await publishRelease({
      releasesRoot: root,
      artifact: fakeArtifact(),
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });

    // A symlink planted at the canonical release id must not be followed.
    const realDir = join(root, `${releaseId}-real`);
    await rename(join(root, releaseId), realDir);
    await symlink(realDir, join(root, releaseId));
    await assert.rejects(readRelease(root, releaseId), /real directory/);
    await assert.rejects(switchCurrent(root, releaseId), /real directory/);

    // A symlinked shell inside a real release directory is refused too.
    await rm(join(root, releaseId), { force: true });
    await rename(realDir, join(root, releaseId));
    const realShell = join(root, releaseId, `${SHELL_DIR}-real`);
    await rename(join(root, releaseId, SHELL_DIR), realShell);
    await symlink(realShell, join(root, releaseId, SHELL_DIR));
    await assert.rejects(readRelease(root, releaseId), /real directory/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("a symlinked or non-regular manifest/artifact is refused", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-file-symlink-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-file-symlink-src-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    const { releaseId } = await publishRelease({
      releasesRoot: root,
      artifact: fakeArtifact(),
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });
    const releaseDir = join(root, releaseId);
    await readRelease(root, releaseId);

    // Symlinked artifact must not be followed.
    const realArtifact = join(releaseDir, "artifact-real.bin");
    await rename(join(releaseDir, ARTIFACT_FILE), realArtifact);
    await symlink(realArtifact, join(releaseDir, ARTIFACT_FILE));
    await assert.rejects(readRelease(root, releaseId), /artifact must be a real regular file/);
    await rm(join(releaseDir, ARTIFACT_FILE), { force: true });
    await rename(realArtifact, join(releaseDir, ARTIFACT_FILE));

    // Symlinked manifest must not be followed.
    const realManifest = join(releaseDir, "manifest-real.json");
    await rename(join(releaseDir, MANIFEST_FILE), realManifest);
    await symlink(realManifest, join(releaseDir, MANIFEST_FILE));
    await assert.rejects(readRelease(root, releaseId), /manifest must be a real regular file/);
    await rm(join(releaseDir, MANIFEST_FILE), { force: true });
    await rename(realManifest, join(releaseDir, MANIFEST_FILE));

    // A non-regular entry at the artifact path is refused too.
    await rm(join(releaseDir, ARTIFACT_FILE));
    await mkdir(join(releaseDir, ARTIFACT_FILE));
    await assert.rejects(readRelease(root, releaseId), /artifact must be a real regular file/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("stale staging directories are swept while fresh ones are kept", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-sweep-"));
  try {
    const stale = join(root, ".staging-old");
    const fresh = join(root, ".staging-fresh");
    await mkdir(stale);
    await mkdir(fresh);
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
    await utimes(stale, twoHoursAgo, twoHoursAgo);

    const swept = await sweepStaleStaging(root);
    assert.equal(swept, 1);
    const names = await readdir(root);
    assert.ok(!names.includes(".staging-old"), "stale staging should be removed");
    assert.ok(names.includes(".staging-fresh"), "fresh staging must be preserved");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("republishing the same artifact under a different recipient key is refused", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-recipient-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-recipient-src-"));
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    await publishRelease({
      releasesRoot: root,
      artifact: fakeArtifact(),
      publicKeyB64: PUBLIC_KEY_B64,
      kidB64: KID_B64,
      sourceSha: "9a5a712",
      shellDir,
    });
    // Same artifact id but a different recipient fingerprint must not silently
    // return the stale manifest.
    await assert.rejects(
      publishRelease({
        releasesRoot: root,
        artifact: fakeArtifact(),
        publicKeyB64: Buffer.alloc(32, 8).toString("base64"),
        kidB64: KID_B64,
        sourceSha: "9a5a712",
        shellDir,
      }),
      /immutable/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
  }
});

test("the default payload dir predicate only matches the canonical directory", () => {
  assert.equal(isDefaultPayloadDir(DEFAULT_PAYLOAD_DIR), true);
  assert.equal(isDefaultPayloadDir(resolve(DEFAULT_PAYLOAD_DIR)), true);
  assert.equal(isDefaultPayloadDir(join(tmpdir(), "operator-custom-payload")), false);
});

test("buildAndPublishRelease cleanup removes only a requested payload dir", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-cleanup-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-cleanup-shell-"));
  const cleaned = await mkdtemp(join(tmpdir(), "release-cleanup-on-"));
  const untouched = await mkdtemp(join(tmpdir(), "release-cleanup-off-"));
  const previousKey = process.env.WORKSPACE_PUBLIC_KEY_B64;
  const previousKid = process.env.WORKSPACE_ARTIFACT_KID_B64;
  const previousArtifactKey = process.env.WORKSPACE_ARTIFACT_KEY_B64;
  try {
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    // An exported forbidden key must never leak into a test process.
    delete process.env.WORKSPACE_ARTIFACT_KEY_B64;
    process.env.WORKSPACE_PUBLIC_KEY_B64 = PUBLIC_KEY_B64;
    process.env.WORKSPACE_ARTIFACT_KID_B64 = KID_B64;

    // Empty payload dirs fail packing before sealing, so this exercises the
    // cleanup `finally` on the failure path without invoking the crypto CLI.
    await assert.rejects(
      buildAndPublishRelease({
        releasesRoot: root,
        shellDir,
        payloadDir: cleaned,
        sourceSha: "9a5a712",
        cleanupPayload: true,
      }),
      /file count/,
    );
    await assert.rejects(lstat(cleaned), { code: "ENOENT" });

    await assert.rejects(
      buildAndPublishRelease({
        releasesRoot: root,
        shellDir,
        payloadDir: untouched,
        sourceSha: "9a5a712",
        cleanupPayload: false,
      }),
      /file count/,
    );
    assert.ok((await lstat(untouched)).isDirectory());
  } finally {
    if (previousKey === undefined) delete process.env.WORKSPACE_PUBLIC_KEY_B64;
    else process.env.WORKSPACE_PUBLIC_KEY_B64 = previousKey;
    if (previousKid === undefined) delete process.env.WORKSPACE_ARTIFACT_KID_B64;
    else process.env.WORKSPACE_ARTIFACT_KID_B64 = previousKid;
    if (previousArtifactKey === undefined) delete process.env.WORKSPACE_ARTIFACT_KEY_B64;
    else process.env.WORKSPACE_ARTIFACT_KEY_B64 = previousArtifactKey;
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
    await rm(cleaned, { recursive: true, force: true });
    await rm(untouched, { recursive: true, force: true });
  }
});

test("buildAndPublishRelease integrates build, switch, rollback and headers", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-integration-"));
  const shellDir = await mkdtemp(join(tmpdir(), "release-integration-shell-"));
  const payloadA = await mkdtemp(join(tmpdir(), "release-integration-payload-a-"));
  const payloadB = await mkdtemp(join(tmpdir(), "release-integration-payload-b-"));
  const previousKey = process.env.WORKSPACE_PUBLIC_KEY_B64;
  const previousKid = process.env.WORKSPACE_ARTIFACT_KID_B64;
  const previousArtifactKey = process.env.WORKSPACE_ARTIFACT_KEY_B64;
  try {
    // A temp shell build ships the real production _headers.
    await writeFile(join(shellDir, "_headers"), PRODUCTION_HEADERS);
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    await mkdir(join(shellDir, "assets"));
    await writeFile(join(shellDir, "assets", "index-abc.js"), "console.log(1)");
    await writeFile(join(payloadA, "index.html"), "payload-a");
    await writeFile(join(payloadB, "index.html"), "payload-b");

    // Deterministic non-secret test key material: sealing only needs a valid
    // 32-byte recipient key and 16-byte KID, never a real private key. Delete a
    // forbidden exported key so it cannot fail the build under test.
    delete process.env.WORKSPACE_ARTIFACT_KEY_B64;
    process.env.WORKSPACE_PUBLIC_KEY_B64 = PUBLIC_KEY_B64;
    process.env.WORKSPACE_ARTIFACT_KID_B64 = KID_B64;

    const first = await buildAndPublishRelease({
      releasesRoot: root,
      shellDir,
      payloadDir: payloadA,
      sourceSha: "9a5a712",
      cleanupPayload: true,
    });
    const { manifest: firstManifest } = await readRelease(root, first.releaseId);
    assert.equal(firstManifest.release_id, first.releaseId);

    const second = await buildAndPublishRelease({
      releasesRoot: root,
      shellDir,
      payloadDir: payloadB,
      sourceSha: "beef123",
      cleanupPayload: true,
    });
    assert.notEqual(second.releaseId, first.releaseId);
    assert.equal(await readlink(join(root, CURRENT_LINK)), second.releaseId);
    assert.equal(await readlink(join(root, PREVIOUS_LINK)), first.releaseId);
    await readRelease(root, second.releaseId);

    const rolled = await rollbackCurrent(root);
    assert.equal(rolled.from, second.releaseId);
    assert.equal(rolled.to, first.releaseId);
    assert.equal(await readlink(join(root, CURRENT_LINK)), first.releaseId);
    assert.equal(await readlink(join(root, PREVIOUS_LINK)), second.releaseId);

    // The shipped _headers carries both the hardened block and the exact cache
    // rules the release writer emitted, with the production CSP verbatim.
    const headers = await readFile(join(root, first.releaseId, SHELL_DIR, "_headers"), "utf8");
    assert.match(headers, /^\/\*/m);
    assert.match(headers, /Cache-Control: no-store/);
    assert.match(headers, /X-Content-Type-Options: nosniff/);
    assert.match(headers, /X-Frame-Options: DENY/);
    assert.match(headers, /Referrer-Policy: no-referrer/);
    assert.ok(headers.includes(`Content-Security-Policy: ${PRODUCTION_CSP}`));
    assert.ok(headers.includes("/\n  Cache-Control: no-store, must-revalidate"));
    assert.ok(headers.includes("/index.html\n  Cache-Control: no-store, must-revalidate"));
    assert.ok(
      headers.includes("/assets/*\n  Cache-Control: public, max-age=31536000, immutable"),
    );

    // cleanupPayload removed the plaintext build dirs on the success path.
    await assert.rejects(lstat(payloadA), { code: "ENOENT" });
    await assert.rejects(lstat(payloadB), { code: "ENOENT" });
  } finally {
    if (previousKey === undefined) delete process.env.WORKSPACE_PUBLIC_KEY_B64;
    else process.env.WORKSPACE_PUBLIC_KEY_B64 = previousKey;
    if (previousKid === undefined) delete process.env.WORKSPACE_ARTIFACT_KID_B64;
    else process.env.WORKSPACE_ARTIFACT_KID_B64 = previousKid;
    if (previousArtifactKey === undefined) delete process.env.WORKSPACE_ARTIFACT_KEY_B64;
    else process.env.WORKSPACE_ARTIFACT_KEY_B64 = previousArtifactKey;
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
    await rm(payloadA, { recursive: true, force: true });
    await rm(payloadB, { recursive: true, force: true });
  }
});

test("a dead-PID lock owner is evicted promptly", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-lock-dead-"));
  try {
    const deadPid = await spawnDeadPid();
    const lockPath = await plantLock(root, {
      pid: deadPid,
      token: "dead-owner-token",
      startedAtMs: Date.now(),
    });
    // staleMs is far in the future, so only PID liveness can prove this lock
    // reclaimable: this is the prompt crash-recovery path.
    const owner = await withTimeout(
      acquireReleaseLock(lockPath, { timeoutMs: 2000, staleMs: 60 * 60 * 1000 }),
      4000,
      "dead-owner acquire",
    );
    assert.equal(owner.pid, process.pid);
    await releaseReleaseLock(lockPath, owner);
    await assert.rejects(lstat(lockPath), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a live foreign lock owner is never evicted and acquire times out typed", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-lock-live-"));
  try {
    const foreignToken = "foreign-live-owner";
    const lockPath = await plantLock(root, {
      pid: process.pid, // this process is demonstrably alive
      token: foreignToken,
      startedAtMs: Date.now() - 10 * 60 * 1000,
    });
    // staleMs is tiny, yet an alive owner must survive age-based eviction.
    await assert.rejects(
      acquireReleaseLock(lockPath, { timeoutMs: 150, staleMs: 1 }),
      (error) =>
        error instanceof ReleaseLockTimeoutError && error.code === "RELEASE_LOCK_TIMEOUT",
    );
    const owner = JSON.parse(await readFile(join(lockPath, RELEASE_LOCK_OWNER_FILE), "utf8"));
    assert.equal(owner.token, foreignToken);
    // Releasing with a non-matching token must also leave the live lock alone.
    await releaseReleaseLock(lockPath, { token: "not-the-owner" });
    assert.equal((await lstat(lockPath)).isDirectory(), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a lock is removed only by its owner token", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-lock-token-"));
  try {
    const lockPath = join(root, RELEASE_LOCK_DIR);
    const owner = await acquireReleaseLock(lockPath, { timeoutMs: 1000, staleMs: 1000 });
    // A stale frame holding a different token must not delete this live lock.
    await releaseReleaseLock(lockPath, { token: "someone-else" });
    assert.ok((await lstat(lockPath)).isDirectory(), "mismatched token must not release");
    await releaseReleaseLock(lockPath, owner);
    await assert.rejects(lstat(lockPath), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the same-key re-entrant acquisition does not deadlock", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-lock-reentrant-"));
  try {
    const result = await withTimeout(
      withReleaseLock(root, () => withReleaseLock(root, () => 42)),
      4000,
      "same-key re-entrancy",
    );
    assert.equal(result, 42);
    await assert.rejects(lstat(join(root, RELEASE_LOCK_DIR)), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("two concurrent same-root callers never overlap", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-lock-concurrent-"));
  try {
    let active = 0;
    let maxActive = 0;
    const run = () =>
      withReleaseLock(root, async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 30));
        active -= 1;
      });
    await withTimeout(Promise.all([run(), run(), run()]), 6000, "same-root concurrency");
    assert.equal(maxActive, 1, "same-root lock holders must not overlap");
    await assert.rejects(lstat(join(root, RELEASE_LOCK_DIR)), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("nested cross-root acquisition A -> B -> A does not deadlock", async () => {
  const rootA = await mkdtemp(join(tmpdir(), "release-lock-a-"));
  const rootB = await mkdtemp(join(tmpdir(), "release-lock-b-"));
  try {
    const result = await withTimeout(
      withReleaseLock(rootA, () =>
        withReleaseLock(rootB, () => withReleaseLock(rootA, () => "aba")),
      ),
      4000,
      "cross-root re-entrancy",
    );
    assert.equal(result, "aba");
    await assert.rejects(lstat(join(rootA, RELEASE_LOCK_DIR)), { code: "ENOENT" });
    await assert.rejects(lstat(join(rootB, RELEASE_LOCK_DIR)), { code: "ENOENT" });
  } finally {
    await rm(rootA, { recursive: true, force: true });
    await rm(rootB, { recursive: true, force: true });
  }
});

test("writeArtifactAtomically sweeps only stale leftover temp files", async () => {
  const dir = await mkdtemp(join(tmpdir(), "artifact-sweep-"));
  try {
    const destination = join(dir, "blob.bin");
    const stale = join(dir, ".blob.bin.999.1111.deadbeef.tmp");
    const fresh = join(dir, ".blob.bin.999.2222.cafebabe.tmp");
    await writeFile(stale, "leftover");
    await writeFile(fresh, "in-flight");
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
    await utimes(stale, twoHoursAgo, twoHoursAgo);

    await writeArtifactAtomically(destination, Buffer.from("sealed-bytes"));

    await assert.rejects(lstat(stale), { code: "ENOENT" });
    assert.ok((await lstat(fresh)).isFile(), "fresh temp must be preserved");
    assert.deepEqual(await readFile(destination), Buffer.from("sealed-bytes"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("writeArtifactAtomically replaces the artifact only with verified bytes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "artifact-atomic-"));
  try {
    const destination = join(dir, "blob.bin");
    await writeFile(destination, "old-bytes");
    const artifact = Buffer.from("new-sealed-bytes");
    await writeArtifactAtomically(destination, artifact);
    assert.deepEqual(await readFile(destination), artifact);
    assert.equal((await stat(destination)).mode & 0o777, 0o600);
    assert.deepEqual(
      (await readdir(dir)).filter((name) => name.endsWith(".tmp")),
      [],
      "temp artifact leaked",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("writeArtifactAtomically never removes the destination on failure", async () => {
  const dir = await mkdtemp(join(tmpdir(), "artifact-atomic-fail-"));
  try {
    // A non-empty directory at the destination makes the final rename fail
    // after the temp file was written and verified.
    const blocked = join(dir, "blocked");
    await mkdir(blocked);
    await writeFile(join(blocked, "keep"), "keep");
    await assert.rejects(writeArtifactAtomically(blocked, Buffer.from("replacement")));
    assert.deepEqual(await readdir(blocked), ["keep"]);
    assert.deepEqual(
      (await readdir(dir)).filter((name) => name.endsWith(".tmp")),
      [],
      "temp artifact leaked on failure",
    );

    // A read-only directory prevents the temp file from being created at all;
    // the pre-existing destination must still survive. Root bypasses directory
    // permissions, so this assertion only holds for an unprivileged runner.
    const destination = join(dir, "blob.bin");
    await writeFile(destination, "old-bytes");
    if (!IS_ROOT) {
      await chmod(dir, 0o500);
      let rejected = false;
      try {
        await writeArtifactAtomically(destination, Buffer.from("replacement"));
      } catch {
        rejected = true;
      } finally {
        await chmod(dir, 0o700);
      }
      assert.equal(rejected, true);
    }
    assert.equal(await readFile(destination, "utf8"), "old-bytes");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Stable Workspace Root Key operational proof.
//
// This is the mandatory release-operations test: two consecutive releases are
// built using ONLY the stable PUBLIC key (no root secret in the build path),
// the descriptor is switched between them, and the same browser root decrypts
// both with no reseal and no manual operator action.
// ---------------------------------------------------------------------------

test("stable release tooling seals to the fixed context and rejects a foreign KID", () => {
  assert.equal(artifactKidFromEnv({}).toString("base64"), WORKSPACE_ROOT_CONTEXT_B64);
  assert.equal(
    artifactKidFromEnv({
      WORKSPACE_ARTIFACT_KID_B64: WORKSPACE_ROOT_CONTEXT_B64,
    }).toString("base64"),
    WORKSPACE_ROOT_CONTEXT_B64,
  );
  assert.throws(
    () =>
      artifactKidFromEnv({
        WORKSPACE_ARTIFACT_KID_B64: Buffer.alloc(16, 3).toString("base64"),
      }),
    /deprecated|stable workspace context/,
  );
});

test("operational: N and N+1 built from the stable public key decrypt with one root", async () => {
  const rootSecret = randomBytes(32);
  const publicKey = derivePublicKey(
    rootSecret,
    WORKSPACE_ROOT_CONTEXT_BYTES,
    ARTIFACT_VERSION,
  );
  assert.equal(publicKey.length, 32);
  // The recipient identity is a pure function of the root + fixed context, so
  // it is identical for every release.
  assert.deepEqual(
    derivePublicKey(rootSecret, WORKSPACE_ROOT_CONTEXT_BYTES, ARTIFACT_VERSION),
    publicKey,
  );

  const root = await mkdtemp(join(tmpdir(), "root-release-ops-"));
  const shellDir = await mkdtemp(join(tmpdir(), "root-release-ops-shell-"));
  const payloadA = await mkdtemp(join(tmpdir(), "root-release-ops-payload-a-"));
  const payloadB = await mkdtemp(join(tmpdir(), "root-release-ops-payload-b-"));
  const previousKey = process.env.WORKSPACE_PUBLIC_KEY_B64;
  const previousKid = process.env.WORKSPACE_ARTIFACT_KID_B64;
  try {
    await writeFile(join(shellDir, "_headers"), PRODUCTION_HEADERS);
    await writeFile(join(shellDir, "index.html"), "<!doctype html>");
    await mkdir(join(shellDir, "assets"));
    await writeFile(join(shellDir, "assets", "index-abc.js"), "console.log(1)");
    await writeFile(join(payloadA, "index.html"), "release-n");
    await writeFile(join(payloadB, "index.html"), "release-n-plus-1");

    // The build path sees only the public key and no KID override.
    delete process.env.WORKSPACE_ARTIFACT_KID_B64;
    process.env.WORKSPACE_PUBLIC_KEY_B64 = publicKey.toString("base64");

    const first = await buildAndPublishRelease({
      releasesRoot: root,
      shellDir,
      payloadDir: payloadA,
      sourceSha: "aaaa111",
    });
    const second = await buildAndPublishRelease({
      releasesRoot: root,
      shellDir,
      payloadDir: payloadB,
      sourceSha: "bbbb222",
    });
    assert.notEqual(first.releaseId, second.releaseId);

    const { manifest: manifestFirst } = await readRelease(root, first.releaseId);
    const { manifest: manifestSecond } = await readRelease(root, second.releaseId);

    // One stable identity: same envelope KID and same recipient fingerprint.
    assert.equal(manifestFirst.artifact.kid_b64, WORKSPACE_ROOT_CONTEXT_B64);
    assert.equal(manifestSecond.artifact.kid_b64, WORKSPACE_ROOT_CONTEXT_B64);
    assert.equal(
      manifestFirst.recipient.public_key_fingerprint_b64,
      manifestSecond.recipient.public_key_fingerprint_b64,
    );
    // Per-artifact freshness comes from the envelope, so the digests differ.
    assert.notEqual(
      manifestFirst.artifact.sha256_hex,
      manifestSecond.artifact.sha256_hex,
    );

    const artifactFirst = await readFile(
      join(root, first.releaseId, ARTIFACT_FILE),
    );
    const artifactSecond = await readFile(
      join(root, second.releaseId, ARTIFACT_FILE),
    );
    assert.equal(
      artifactFirst.subarray(1, 1 + KID_BYTES).toString("base64"),
      WORKSPACE_ROOT_CONTEXT_B64,
    );
    assert.equal(
      artifactSecond.subarray(1, 1 + KID_BYTES).toString("base64"),
      WORKSPACE_ROOT_CONTEXT_B64,
    );

    // The same browser root unlocks both releases, with no reseal.
    const plainFirst = await decryptArtifact(
      artifactFirst,
      rootSecret,
      WORKSPACE_ROOT_CONTEXT_BYTES,
      ARTIFACT_VERSION,
    );
    const plainSecond = await decryptArtifact(
      artifactSecond,
      rootSecret,
      WORKSPACE_ROOT_CONTEXT_BYTES,
      ARTIFACT_VERSION,
    );
    assert.ok(plainFirst.length > 0);
    assert.ok(plainSecond.length > 0);
    assert.notDeepEqual(plainFirst, plainSecond);

    // Switching the current descriptor back and forth never invalidates either
    // release for the stable root.
    await switchCurrent(root, first.releaseId);
    assert.equal(await readlink(join(root, CURRENT_LINK)), first.releaseId);
    assert.ok(
      (
        await decryptArtifact(
          artifactFirst,
          rootSecret,
          WORKSPACE_ROOT_CONTEXT_BYTES,
          ARTIFACT_VERSION,
        )
      ).length > 0,
    );
    await switchCurrent(root, second.releaseId);
    assert.equal(await readlink(join(root, CURRENT_LINK)), second.releaseId);
    assert.ok(
      (
        await decryptArtifact(
          artifactSecond,
          rootSecret,
          WORKSPACE_ROOT_CONTEXT_BYTES,
          ARTIFACT_VERSION,
        )
      ).length > 0,
    );

    // A different root cannot open either release.
    const otherRoot = randomBytes(32);
    await assert.rejects(
      decryptArtifact(
        artifactFirst,
        otherRoot,
        WORKSPACE_ROOT_CONTEXT_BYTES,
        ARTIFACT_VERSION,
      ),
    );
  } finally {
    if (previousKey === undefined) delete process.env.WORKSPACE_PUBLIC_KEY_B64;
    else process.env.WORKSPACE_PUBLIC_KEY_B64 = previousKey;
    if (previousKid === undefined) delete process.env.WORKSPACE_ARTIFACT_KID_B64;
    else process.env.WORKSPACE_ARTIFACT_KID_B64 = previousKid;
    await rm(root, { recursive: true, force: true });
    await rm(shellDir, { recursive: true, force: true });
    await rm(payloadA, { recursive: true, force: true });
    await rm(payloadB, { recursive: true, force: true });
  }
});
