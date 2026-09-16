// Immutable workspace release publication and rollback.
//
// A release binds the exact bytes that must move together:
//   releases/<release-id>/
//     manifest.json        immutable, self-describing release identity
//     workspace.artifact   sealed workspace package (mode 0600)
//     shell/               immutable clear-shell build (hashed assets)
//
// Publication is copy-then-validate-then-switch: a new release directory is
// written and validated in full before the `current` symlink is atomically
// renamed onto it. The previous target is retained as `previous`, so rollback
// is a second atomic rename and never rewrites a released directory.
//
// The manifest carries only public metadata: release id, source commit, artifact
// version/KID/size/SHA-256, the recipient public-key fingerprint, the package
// format version, and the workspace protocol range. The private-API validates
// the same manifest against the artifact bytes before it will deliver anything.

import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomBytes } from "node:crypto";
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  symlink,
} from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import {
  ARTIFACT_VERSION,
  KID_BYTES,
  MIN_ARTIFACT_BYTES,
  PUBLIC_KEY_BYTES,
  TAG_BYTES,
  artifactKidFromEnv,
  artifactPublicKeyFromEnv,
  packDirectory,
  sealPackage,
} from "./workspace-artifact.mjs";

export const RELEASE_MANIFEST_VERSION = 1;
export const PACKAGE_FORMAT_VERSION = 1;
export const WORKSPACE_PROTOCOL_VERSION = 1;
export const MANIFEST_FILE = "manifest.json";
export const ARTIFACT_FILE = "workspace.artifact";
export const SHELL_DIR = "shell";
export const CURRENT_LINK = "current";
export const PREVIOUS_LINK = "previous";
/** Canonical plaintext payload directory; the only path `build` may clean up. */
export const DEFAULT_PAYLOAD_DIR = "web/workspace-payload/dist";
/** Advisory lock directory created inside the releases root. */
export const RELEASE_LOCK_DIR = ".release.lock";

function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Write a file and fsync it before returning, so a subsequent atomic rename
 * cannot expose a directory whose bytes are not yet durable after power loss.
 */
async function writeFileDurable(path, data, options = {}) {
  const handle = await open(path, "w", options.mode ?? 0o644);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/**
 * Best-effort directory fsync. Directory fsync is not supported on every
 * platform/filesystem; the per-file fsync above is the important barrier.
 */
async function syncDirectory(path) {
  let handle;
  try {
    handle = await open(path, "r");
    await handle.sync();
  } catch {
    // Not supported here; ignore.
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

/** Best-effort file fsync for copies made outside `writeFileDurable`. */
async function syncFile(path) {
  let handle;
  try {
    handle = await open(path, "r+");
    await handle.sync();
  } catch {
    // Not every file/filsystem permits a sync; ignore.
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

export const RELEASE_LOCK_OWNER_FILE = "owner.json";
/**
 * Bounded acquire timeout. Chosen to be >= {@link RELEASE_LOCK_STALE_MS} so a
 * single invocation can recover from an unreadable owner stamp. Prompt
 * recovery does not depend on the timeout: a lock whose recorded pid is dead is
 * evicted immediately via `process.kill(pid, 0)`.
 */
export const RELEASE_LOCK_TIMEOUT_MS = 6 * 60 * 1000;
export const RELEASE_LOCK_STALE_MS = 5 * 60 * 1000;
const RELEASE_LOCK_POLL_MS = 20;

/** Typed acquire failure: the lock is held by a live owner, not broken. */
export class ReleaseLockTimeoutError extends Error {
  constructor(message = "timed out acquiring release lock") {
    super(message);
    this.name = "ReleaseLockTimeoutError";
    this.code = "RELEASE_LOCK_TIMEOUT";
  }
}

// In-process serialization per resolved releases root, so two async callers in
// the same process cannot both believe they hold the on-disk lock.
const releaseLockTails = new Map();
// AsyncLocalStorage makes the lock re-entrant within a single call chain: a
// nested acquisition reuses the lock the outer frame already holds instead of
// deadlocking on it.
const releaseLockContext = new AsyncLocalStorage();

function randomToken() {
  return randomBytes(16).toString("hex");
}

/** True only while a live process still owns `pid` (EPERM means alive). */
function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== "ESRCH";
  }
}

async function readLockOwner(lockPath) {
  try {
    const parsed = JSON.parse(await readFile(join(lockPath, RELEASE_LOCK_OWNER_FILE), "utf8"));
    if (!parsed || typeof parsed !== "object") return null;
    return parsed;
  } catch {
    // Missing, unreadable, or unparseable ownership is unknown, never "ours".
    return null;
  }
}

async function writeLockOwner(lockPath, owner) {
  await writeFileDurable(
    join(lockPath, RELEASE_LOCK_OWNER_FILE),
    `${JSON.stringify(owner)}\n`,
    { mode: 0o644 },
  );
}

/**
 * Move a contended lock aside and delete it. Renaming first means the loser of
 * an eviction race only ever touches its own unique tombstone, and re-checking
 * the moved owner prevents eviction from deleting a newer live lock that was
 * created between the staleness check and the rename.
 */
async function evictLock(lockPath) {
  const tombstone = `${lockPath}.${process.pid}.${Date.now()}.${randomToken()}.tombstone`;
  try {
    await rename(lockPath, tombstone);
  } catch (error) {
    if (error?.code === "ENOENT") return; // another contender already evicted it
    throw error;
  }
  const moved = await readLockOwner(tombstone);
  if (moved && Number.isInteger(moved.pid) && isProcessAlive(moved.pid)) {
    // A live owner appeared in the race window; restore it rather than delete it.
    await rename(tombstone, lockPath).catch(async () => {
      await rm(tombstone, { recursive: true, force: true }).catch(() => {});
    });
    return;
  }
  await rm(tombstone, { recursive: true, force: true }).catch(() => {});
}

/**
 * Acquire the advisory lock directory, writing an owner stamp (`pid`, random
 * `token`, `startedAtMs`) inside it. On contention the lock is evicted only
 * when it is provably dead (recorded pid no longer exists) or, for an
 * unreadable owner stamp, older than `staleMs`. A lock whose pid is alive is
 * never evicted, so a slow or suspended holder cannot be displaced.
 */
export async function acquireReleaseLock(
  lockPath,
  { timeoutMs = RELEASE_LOCK_TIMEOUT_MS, staleMs = RELEASE_LOCK_STALE_MS } = {},
) {
  const deadline = Date.now() + timeoutMs;
  const owner = { pid: process.pid, token: randomToken(), startedAtMs: Date.now() };
  for (;;) {
    try {
      await mkdir(lockPath);
      try {
        await writeLockOwner(lockPath, owner);
      } catch (error) {
        // Never leave behind a lock we cannot prove is ours.
        await rm(lockPath, { recursive: true, force: true }).catch(() => {});
        throw error;
      }
      return owner;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
    }
    let evict = false;
    try {
      const stat = await lstat(lockPath);
      if (!stat.isDirectory()) {
        evict = true;
      } else {
        const existing = await readLockOwner(lockPath);
        if (existing && Number.isInteger(existing.pid)) {
          // PID liveness gives prompt crash recovery; an alive owner is never
          // evicted no matter how old its stamp is.
          evict = !isProcessAlive(existing.pid);
        } else if (Date.now() - stat.mtimeMs > staleMs) {
          // Only an unreadable owner stamp may age out, and only past the bound.
          evict = true;
        }
      }
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    if (evict) {
      await evictLock(lockPath);
      continue;
    }
    if (Date.now() >= deadline) throw new ReleaseLockTimeoutError();
    await delay(RELEASE_LOCK_POLL_MS);
  }
}

/**
 * Release a lock only while this holder still owns it. Renaming to a unique
 * tombstone first and re-checking the token inside it stops an evicted holder
 * from deleting a newer holder's lock that appeared in the meantime.
 */
export async function releaseReleaseLock(lockPath, owner) {
  const token = owner?.token;
  if (typeof token !== "string" || token.length === 0) return;
  if ((await readLockOwner(lockPath))?.token !== token) return;
  const tombstone = `${lockPath}.${process.pid}.${Date.now()}.${randomToken()}.tombstone`;
  try {
    await rename(lockPath, tombstone);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  if ((await readLockOwner(tombstone))?.token === token) {
    await rm(tombstone, { recursive: true, force: true }).catch(() => {});
    return;
  }
  // We moved someone else's re-created lock; restore it rather than delete it.
  await rename(tombstone, lockPath).catch(async () => {
    await rm(tombstone, { recursive: true, force: true }).catch(() => {});
  });
}

/**
 * Run `fn` while holding the per-releases-root advisory lock: an atomically
 * created directory inside the releases root, with a bounded acquire timeout
 * and an owner-stamped crash-recovery guard. Re-entrant within one async call
 * chain, and serialized in-process per root.
 */
export async function withReleaseLock(releasesRoot, fn) {
  const key = resolve(releasesRoot);
  const held = releaseLockContext.getStore();
  if (held?.has(key)) return fn();

  const prior = releaseLockTails.get(key) ?? Promise.resolve();
  let unlock;
  const gate = new Promise((releaseGate) => {
    unlock = releaseGate;
  });
  const chained = prior.then(() => gate);
  releaseLockTails.set(key, chained);
  await prior;

  const lockPath = join(key, RELEASE_LOCK_DIR);
  let owner = null;
  try {
    // The releases root must exist before the lock directory can be created.
    await mkdir(key, { recursive: true });
    owner = await acquireReleaseLock(lockPath, {
      timeoutMs: RELEASE_LOCK_TIMEOUT_MS,
      staleMs: RELEASE_LOCK_STALE_MS,
    });
    // Extend, do not replace, the held-key set so a nested cross-root chain
    // (A -> B -> A) still sees A as re-entrant.
    return await releaseLockContext.run(new Map([...(held ?? []), [key, 1]]), () => fn());
  } finally {
    if (owner) await releaseReleaseLock(lockPath, owner).catch(() => {});
    unlock();
    if (releaseLockTails.get(key) === chained) releaseLockTails.delete(key);
  }
}

function publicKeyFingerprintB64(publicKey) {
  return createHash("sha256").update(publicKey).digest("base64");
}

/** Deterministic digest over a directory tree (paths + bytes), hex. */
export async function digestDirectory(root) {
  const rootResolved = resolve(root);
  // Reject a symlinked root as well as symlinks inside the tree, so a caller
  // cannot be redirected to hash a directory outside the release.
  const rootStat = await lstat(rootResolved);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new Error("release tree root must be a real directory");
  }
  const entries = [];
  async function walk(dir) {
    const names = (await readdir(dir)).sort();
    for (const name of names) {
      const full = join(dir, name);
      const stat = await lstat(full);
      if (stat.isSymbolicLink()) throw new Error("symlinks are not allowed in a release tree");
      if (stat.isDirectory()) await walk(full);
      else if (stat.isFile()) entries.push(full);
      else throw new Error("unsupported release tree entry");
    }
  }
  await walk(rootResolved);
  const hash = createHash("sha256");
  for (const file of entries) {
    const rel = relative(rootResolved, file).split(sep).join("/");
    hash.update(rel);
    hash.update("\0");
    hash.update(await readFile(file));
    hash.update("\0");
  }
  return hash.digest("hex");
}

/** Derive a stable release id from the source commit and artifact digest. */
export function releaseIdFor(sourceSha, artifactDigestHex) {
  // The id becomes a directory name, so only hex survives. A non-hex or empty
  // source sha cannot escape the releases root.
  const sha = String(sourceSha ?? "")
    .toLowerCase()
    .replace(/[^0-9a-f]/g, "")
    .slice(0, 12);
  if (!sha) throw new Error("source sha must contain hex characters");
  return `${sha}-${artifactDigestHex.slice(0, 12)}`;
}

/** The exact shape `releaseIdFor` emits; also the only safe path component. */
const RELEASE_ID_PATTERN = /^[0-9a-f]{1,12}-[0-9a-f]{12}$/;

/** Reject any release id that is not a single canonical directory name. */
export function assertReleaseId(releaseId) {
  if (typeof releaseId !== "string" || !RELEASE_ID_PATTERN.test(releaseId)) {
    throw new Error("invalid release id");
  }
  return releaseId;
}

/** Build the immutable manifest for an already-sealed artifact. */
export function computeReleaseManifest({
  releaseId,
  sourceSha,
  artifact,
  publicKeyB64,
  kidB64,
  shellAssetDigest,
  artifactVersion = ARTIFACT_VERSION,
}) {
  if (!Buffer.isBuffer(artifact) || artifact.length === 0) {
    throw new Error("artifact bytes required");
  }
  const publicKey = Buffer.from(publicKeyB64, "base64");
  if (publicKey.length !== PUBLIC_KEY_BYTES) throw new Error("invalid public key");
  const kid = Buffer.from(kidB64, "base64");
  if (kid.length !== KID_BYTES) throw new Error("invalid kid");
  if (!releaseId || typeof releaseId !== "string") throw new Error("release id required");
  if (!sourceSha || typeof sourceSha !== "string") throw new Error("source sha required");
  if (!shellAssetDigest || !/^[0-9a-f]+$/.test(shellAssetDigest)) {
    throw new Error("shell asset digest required");
  }
  return {
    manifest_version: RELEASE_MANIFEST_VERSION,
    release_id: releaseId,
    source_sha: sourceSha,
    artifact: {
      version: artifactVersion,
      kid_b64: kidB64,
      sha256_hex: sha256Hex(artifact),
      size: artifact.length,
      package_format_version: PACKAGE_FORMAT_VERSION,
    },
    recipient: {
      public_key_fingerprint_b64: publicKeyFingerprintB64(publicKey),
    },
    workspace_protocol: {
      min: WORKSPACE_PROTOCOL_VERSION,
      max: WORKSPACE_PROTOCOL_VERSION,
    },
    shell: {
      asset_digest_hex: shellAssetDigest,
    },
  };
}

/**
 * Validate that a manifest describes exactly these artifact bytes. Throws with
 * a generic reason; never includes paths or secrets.
 */
export function validateReleaseManifest(manifest, artifact) {
  if (!manifest || typeof manifest !== "object") throw new Error("manifest missing");
  if (manifest.manifest_version !== RELEASE_MANIFEST_VERSION) {
    throw new Error("unsupported manifest version");
  }
  if (!manifest.release_id || !manifest.source_sha) throw new Error("manifest identity incomplete");
  if (!manifest.artifact || typeof manifest.artifact !== "object") {
    throw new Error("manifest artifact missing");
  }
  if (!manifest.recipient || typeof manifest.recipient !== "object") {
    throw new Error("manifest recipient missing");
  }
  if (!manifest.workspace_protocol || typeof manifest.workspace_protocol !== "object") {
    throw new Error("manifest protocol missing");
  }
  if (!Buffer.isBuffer(artifact) || artifact.length < MIN_ARTIFACT_BYTES) {
    throw new Error("artifact missing or truncated");
  }
  // Parse the bounded artifact header exactly as the server and browser do, so
  // a zero-KID or non-v1 artifact cannot pass a client-side "validate".
  if (artifact[0] !== ARTIFACT_VERSION) throw new Error("unsupported artifact version");
  if (manifest.artifact.version !== ARTIFACT_VERSION) {
    throw new Error("artifact version mismatch");
  }
  const kidBytes = artifact.subarray(1, 1 + KID_BYTES);
  if (kidBytes.every((byte) => byte === 0)) throw new Error("zero artifact kid");
  const encapsulated = artifact.subarray(1 + KID_BYTES, 1 + KID_BYTES + 32);
  if (encapsulated.length !== 32 || encapsulated.every((byte) => byte === 0)) {
    throw new Error("invalid artifact encapsulated key");
  }
  if (artifact.length - (1 + KID_BYTES + 32) < TAG_BYTES) {
    throw new Error("artifact ciphertext too short");
  }
  const kidB64 = kidBytes.toString("base64");
  if (kidB64 !== manifest.artifact.kid_b64) throw new Error("artifact kid mismatch");
  if (artifact.length !== manifest.artifact.size) throw new Error("artifact size mismatch");
  if (sha256Hex(artifact) !== manifest.artifact.sha256_hex) throw new Error("artifact digest mismatch");
  if (manifest.artifact.package_format_version !== PACKAGE_FORMAT_VERSION) {
    throw new Error("unsupported package format");
  }
  if (
    !manifest.shell ||
    typeof manifest.shell.asset_digest_hex !== "string" ||
    !/^[0-9a-f]{64}$/.test(manifest.shell.asset_digest_hex)
  ) {
    throw new Error("invalid shell asset digest");
  }
  const protocol = manifest.workspace_protocol;
  const validProtocolByte = (value) =>
    Number.isInteger(value) && value >= 0 && value <= 255;
  if (
    !protocol ||
    !validProtocolByte(protocol.min) ||
    !validProtocolByte(protocol.max) ||
    protocol.min > protocol.max ||
    protocol.min > WORKSPACE_PROTOCOL_VERSION ||
    protocol.max < WORKSPACE_PROTOCOL_VERSION
  ) {
    throw new Error("incompatible workspace protocol");
  }
  const fingerprintB64 = manifest.recipient?.public_key_fingerprint_b64 ?? "";
  const fingerprint = Buffer.from(fingerprintB64, "base64");
  if (
    fingerprint.length !== 32 ||
    fingerprint.toString("base64") !== fingerprintB64
  ) {
    throw new Error("invalid recipient fingerprint");
  }
  return manifest;
}

export const HARDENED_CSP =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' blob:; style-src 'self' blob:; " +
  "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-src blob:; " +
  "worker-src 'self' blob: data:; object-src 'none'; base-uri 'none'; form-action 'self'; " +
  "frame-ancestors 'none'";

// Same hardened header set as web/workspace-shell/public/_headers.
const HARDENED_WILDCARD_BLOCK = [
  "/*",
  "  Cache-Control: no-store",
  "  X-Content-Type-Options: nosniff",
  "  X-Frame-Options: DENY",
  "  Referrer-Policy: no-referrer",
  `  Content-Security-Policy: ${HARDENED_CSP}`,
].join("\n");

/** Paths whose cache policy the release writer owns end-to-end. */
const MANAGED_CACHE_PATHS = ["/", "/index.html", "/assets/*"];

const SHELL_CACHE_RULES = [
  "/",
  "  Cache-Control: no-store, must-revalidate",
  "",
  "/index.html",
  "  Cache-Control: no-store, must-revalidate",
  "",
  "/assets/*",
  "  Cache-Control: public, max-age=31536000, immutable",
].join("\n");

const REQUIRED_WILDCARD_HEADERS = [
  [
    "cache-control",
    (value) => value.split(",").some((part) => part.trim().toLowerCase() === "no-store"),
  ],
  ["x-content-type-options", (value) => value.trim().toLowerCase() === "nosniff"],
  ["x-frame-options", (value) => value.trim().toUpperCase() === "DENY"],
  ["referrer-policy", (value) => value.trim().toLowerCase() === "no-referrer"],
  // Exact match modulo surrounding whitespace: rejects `default-src *` and any
  // other weakened policy instead of merely probing for a directive name.
  ["content-security-policy", (value) => value.trim() === HARDENED_CSP],
];

/** Parse `_headers`-style text into ordered `{ path, headers }` rules. */
function parseHeaderRules(text) {
  const rules = [];
  let current = null;
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.replace(/\s+$/, "");
    const trimmed = line.trim();
    // Blank lines and `#` comments never create a rule and never detach the
    // headers that follow: a column-0 comment must not become a path that
    // steals the subsequent header lines.
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    if (/^\s/.test(line)) {
      const match = /^\s+([A-Za-z0-9-]+)\s*:\s*(.*)$/.exec(line);
      if (current && match) current.headers.set(match[1].toLowerCase(), match[2].trim());
      continue;
    }
    current = { path: trimmed, headers: new Map() };
    rules.push(current);
  }
  return rules;
}

/** Split raw `_headers` text into blank-line-separated rule blocks. */
function splitHeaderBlocks(text) {
  const blocks = [];
  let current = [];
  for (const line of String(text).split(/\r?\n/)) {
    if (line.trim() === "") {
      if (current.length > 0) blocks.push(current);
      current = [];
      continue;
    }
    current.push(line);
  }
  if (current.length > 0) blocks.push(current);
  return blocks;
}

/**
 * Throw unless the `_headers` text has at least one `/*` rule and *every* `/*`
 * rule carries the complete hardened header set. Checking only the first would
 * let a later weaker wildcard survive publication.
 */
function assertHardenedWildcard(text) {
  const wildcards = parseHeaderRules(text).filter((rule) => rule.path === "/*");
  if (wildcards.length === 0) {
    throw new Error("shell _headers is missing the hardened /* rule");
  }
  for (const wildcard of wildcards) {
    for (const [name, acceptable] of REQUIRED_WILDCARD_HEADERS) {
      const value = wildcard.headers.get(name);
      if (!value || !acceptable(value)) {
        throw new Error(`shell _headers /* rule is missing hardened ${name}`);
      }
    }
  }
}

/**
 * Drop only the managed paths' `Cache-Control` header lines, preserving every
 * other header (HSTS and friends) in their blocks so re-running stays
 * idempotent without discarding unrelated hardening. A managed path left with
 * no other headers is dropped; its canonical rule is re-appended after.
 */
function withoutCacheRules(text) {
  const blocks = splitHeaderBlocks(text).flatMap((block) => {
    if (!MANAGED_CACHE_PATHS.includes(block[0].trim())) return [block];
    const kept = block.filter(
      (line, index) => index === 0 || !/^\s+cache-control\s*:/i.test(line),
    );
    return kept.length > 1 ? [kept] : [];
  });
  return blocks.map((block) => block.join("\n")).join("\n\n");
}

/**
 * Add cache rules to the shell `_headers` **without dropping the hardened
 * security headers** the shell build ships. HTML revalidates, hashed assets are
 * immutable; the hardened `/*` rule (CSP, nosniff, frame-deny, referrer policy,
 * no-store) is preserved because a release must never weaken the clear shell
 * that hosts the recovery-code input. An existing `_headers` that lacks the
 * hardened `/*` rule is refused rather than silently patched, and an absent
 * `_headers` gets the complete hardened block, never a bare Cache-Control.
 */
export async function writeShellCacheHeaders(shellDir) {
  const headersPath = join(shellDir, "_headers");
  let existing = null;
  try {
    existing = await readFile(headersPath, "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  let base = HARDENED_WILDCARD_BLOCK;
  if (existing !== null) {
    assertHardenedWildcard(existing);
    base = withoutCacheRules(existing).trim() || HARDENED_WILDCARD_BLOCK;
  }
  await writeFileDurable(headersPath, `${base.trimEnd()}\n\n${SHELL_CACHE_RULES}\n`, {
    mode: 0o644,
  });
}

async function linkTarget(linkPath) {
  try {
    return await readlink(linkPath);
  } catch {
    return null;
  }
}

async function atomicSymlink(linkPath, target) {
  const parent = dirname(linkPath);
  const tmp = join(parent, `.${Date.now()}-${process.pid}-${Math.random().toString(36).slice(2)}.tmp`);
  try {
    await symlink(target, tmp);
    await rename(tmp, linkPath);
  } catch (error) {
    // A failed symlink/rename (e.g. a read-only releases root) must not leak a
    // half-created temp link into the releases directory.
    await rm(tmp, { force: true }).catch(() => {});
    throw error;
  }
  // Make the rename durable before the caller proceeds to the paired symlink.
  await syncDirectory(parent);
}

/**
 * Atomically point `current` at an existing validated release under the
 * releases-root advisory lock.
 */
export async function switchCurrent(releasesRoot, releaseId) {
  const id = assertReleaseId(releaseId);
  await withReleaseLock(releasesRoot, () => switchCurrentLocked(releasesRoot, id));
  return id;
}

async function switchCurrentLocked(releasesRoot, releaseId) {
  const id = assertReleaseId(releaseId);
  const releaseDir = join(releasesRoot, id);
  // A release is only switchable after its manifest, artifact bytes and shell
  // digest all validate.
  await readRelease(releasesRoot, id);
  const currentPath = join(releasesRoot, CURRENT_LINK);
  const previousPath = join(releasesRoot, PREVIOUS_LINK);
  const current = await linkTarget(currentPath);
  if (current && current !== id) {
    await atomicSymlink(previousPath, current);
  }
  await atomicSymlink(currentPath, id);
  return id;
}

/**
 * Swap `current` and `previous` for rollback, under the advisory lock. Each
 * symlink replacement is atomic; the pair is not a single atomic operation, so
 * a crash between the two renames leaves `current` and `previous` pointing at
 * the same valid release (never a missing or half-written one).
 */
export async function rollbackCurrent(releasesRoot) {
  return withReleaseLock(releasesRoot, () => rollbackCurrentLocked(releasesRoot));
}

async function rollbackCurrentLocked(releasesRoot) {
  const currentPath = join(releasesRoot, CURRENT_LINK);
  const previousPath = join(releasesRoot, PREVIOUS_LINK);
  const current = await linkTarget(currentPath);
  const previous = await linkTarget(previousPath);
  if (!previous) throw new Error("no previous release to roll back to");
  if (!current) throw new Error("no current release to roll back from");
  // The crash window between the two renames can leave both links on the same
  // release; rolling back would be a silent no-op, so refuse explicitly.
  if (current === previous) {
    throw new Error("current and previous are the same release; nothing to roll back");
  }
  // Both targets are attacker-influencable link contents: validate each as a
  // real, fully-checked release before touching either symlink.
  await readRelease(releasesRoot, current);
  await readRelease(releasesRoot, previous);
  await atomicSymlink(previousPath, current);
  await atomicSymlink(currentPath, previous);
  return { from: current, to: previous };
}

/**
 * Read and fully validate a published release: manifest vs artifact bytes and
 * the shell tree digest the manifest binds.
 */
export async function readRelease(releasesRoot, releaseId) {
  const id = assertReleaseId(releaseId);
  const releaseDir = join(releasesRoot, id);
  // A release directory and its shell tree must be real directories inside the
  // releases root: a symlink planted at either path must never be followed,
  // validated and served from outside the root.
  const rootReal = await realpath(releasesRoot);
  const dirStat = await lstat(releaseDir);
  if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
    throw new Error("release directory must be a real directory");
  }
  if ((await realpath(releaseDir)) !== join(rootReal, id)) {
    throw new Error("release directory escapes the releases root");
  }
  const shellPath = join(releaseDir, SHELL_DIR);
  const shellStat = await lstat(shellPath);
  if (shellStat.isSymbolicLink() || !shellStat.isDirectory()) {
    throw new Error("release shell must be a real directory");
  }
  // The manifest and artifact must be real regular files: a symlink (or any
  // non-regular entry) planted at either name must never be followed.
  const manifestPath = join(releaseDir, MANIFEST_FILE);
  const artifactPath = join(releaseDir, ARTIFACT_FILE);
  const manifestStat = await lstat(manifestPath);
  if (manifestStat.isSymbolicLink() || !manifestStat.isFile()) {
    throw new Error("release manifest must be a real regular file");
  }
  const artifactStat = await lstat(artifactPath);
  if (artifactStat.isSymbolicLink() || !artifactStat.isFile()) {
    throw new Error("release artifact must be a real regular file");
  }
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const artifact = await readFile(artifactPath);
  validateReleaseManifest(manifest, artifact);
  // The manifest must describe *this* directory, not merely a self-consistent
  // release elsewhere: reject a renamed/copied directory whose identity differs.
  if (manifest.release_id !== id) {
    throw new Error("manifest release id does not match its directory");
  }
  if (releaseIdFor(manifest.source_sha, manifest.artifact.sha256_hex) !== id) {
    throw new Error("manifest does not derive its own release id");
  }
  const shellDigest = await digestDirectory(shellPath);
  if (shellDigest !== manifest.shell.asset_digest_hex) {
    throw new Error("shell asset digest mismatch");
  }
  return { releaseDir, manifest, artifact };
}

/**
 * Remove stale staging directories left by a killed publish. Only directories
 * older than one hour are swept, so a concurrent in-flight publish is never
 * disturbed.
 */
export async function sweepStaleStaging(releasesRoot, nowMs = Date.now(), maxAgeMs = 60 * 60 * 1000) {
  let names;
  try {
    names = await readdir(releasesRoot);
  } catch {
    return 0;
  }
  let swept = 0;
  for (const name of names) {
    if (!name.startsWith(".staging-")) continue;
    const full = join(releasesRoot, name);
    try {
      const stat = await lstat(full);
      if (stat.isSymbolicLink() || !stat.isDirectory()) continue;
      if (nowMs - stat.mtimeMs < maxAgeMs) continue;
      await rm(full, { recursive: true, force: true });
      swept += 1;
    } catch {
      // A concurrent publish may have consumed it; ignore.
    }
  }
  return swept;
}

/**
 * Publish a new immutable release: copy the sealed artifact and shell build,
 * write the manifest, validate the whole directory, then atomically switch.
 * Never mutates an existing release directory.
 */
export async function publishRelease({
  releasesRoot,
  artifact,
  publicKeyB64,
  kidB64,
  sourceSha,
  shellDir,
}) {
  const artifactDigest = sha256Hex(artifact);
  const releaseId = releaseIdFor(sourceSha, artifactDigest);
  const releaseDir = join(releasesRoot, releaseId);
  // The staging directory is created by `mkdtemp` below, which requires the
  // releases root to exist.
  await mkdir(releasesRoot, { recursive: true });
  // Best-effort sweep of staging directories leaked by a previous killed
  // publish; age-bounded so a concurrent publish is never disturbed.
  await sweepStaleStaging(releasesRoot);
  // Resolve the operator-supplied source shell directory once. A symlinked
  // *source* is legitimate; symlinks *inside* a published release tree are
  // still refused.
  const shellSource = await realpath(shellDir);
  const shellAssetDigest = await digestDirectory(shellSource);
  const manifest = computeReleaseManifest({
    releaseId,
    sourceSha,
    artifact,
    publicKeyB64,
    kidB64,
    shellAssetDigest,
  });
  const staging = await mkdtemp(join(releasesRoot, ".staging-"));
  let shippedShellDigest;
  try {
    await writeFileDurable(join(staging, ARTIFACT_FILE), artifact, { mode: 0o600 });
    const stagedShell = join(staging, SHELL_DIR);
    await mkdir(stagedShell, { recursive: true });
    await copyTree(shellSource, stagedShell);
    await writeShellCacheHeaders(stagedShell);
    // Fsync the shell root itself after it is populated (copyTree only syncs
    // nested directories), so top-level entries are as durable as the rest.
    await syncDirectory(stagedShell);
    // The manifest covers the shell as shipped (including _headers).
    shippedShellDigest = await digestDirectory(stagedShell);
    manifest.shell.asset_digest_hex = shippedShellDigest;
    await writeFileDurable(
      join(staging, MANIFEST_FILE),
      `${JSON.stringify(manifest, null, 2)}\n`,
      { mode: 0o644 },
    );
    validateReleaseManifest(manifest, artifact);
    await syncDirectory(staging);
  } catch (error) {
    await rm(staging, { recursive: true, force: true }).catch(() => {});
    throw error;
  }

  // From here on the staging directory must never leak, even when an existing
  // release cannot be read or the final rename fails. The existence check,
  // rename and switch happen under the releases-root lock; an existing release
  // is revalidated and switched through the internal unlocked switch so the
  // lock is acquired exactly once (no self-deadlock).
  return withReleaseLock(releasesRoot, async () => {
    let published = false;
    try {
      let exists = false;
      try {
        await lstat(releaseDir);
        exists = true;
      } catch (error) {
        // Only a genuinely absent directory means "new release"; any other stat
        // failure (EACCES/EIO) must not be treated as absent.
        if (error?.code !== "ENOENT") throw error;
      }
      if (exists) {
        // Re-publishing is idempotent only when the release is byte-identical:
        // same artifact AND same shipped shell digest. The release id is derived
        // from the artifact, so a shell-only change under the same source SHA must
        // be refused rather than silently switching to the stale shell.
        const existing = await readRelease(releasesRoot, releaseId);
        if (
          !existing.artifact.equals(artifact) ||
          existing.manifest.shell.asset_digest_hex !== shippedShellDigest ||
          existing.manifest.source_sha !== manifest.source_sha ||
          existing.manifest.artifact.kid_b64 !== manifest.artifact.kid_b64 ||
          existing.manifest.recipient.public_key_fingerprint_b64 !==
            manifest.recipient.public_key_fingerprint_b64
        ) {
          throw new Error("release already exists and is immutable");
        }
        await switchCurrentLocked(releasesRoot, releaseId);
        return { releaseId, manifest: existing.manifest };
      }

      await rename(staging, releaseDir);
      published = true;
      await syncDirectory(releasesRoot);
      await switchCurrentLocked(releasesRoot, releaseId);
      return { releaseId, manifest };
    } finally {
      if (!published) {
        await rm(staging, { recursive: true, force: true }).catch(() => {});
      }
    }
  });
}

async function copyTree(source, destination) {
  const names = (await readdir(source)).sort();
  for (const name of names) {
    const from = join(source, name);
    const to = join(destination, name);
    const stat = await lstat(from);
    if (stat.isSymbolicLink()) throw new Error("symlinks are not allowed in a shell build");
    if (stat.isDirectory()) {
      await mkdir(to, { recursive: true });
      await copyTree(from, to);
      // Sync *after* the directory is populated, so its entries are durable.
      await syncDirectory(to);
    } else if (stat.isFile()) {
      await copyFile(from, to);
      await syncFile(to);
    } else {
      throw new Error("unsupported shell build entry");
    }
  }
}

/**
 * True only for the canonical plaintext payload directory. The plaintext build
 * directory may be cleaned up after sealing, but never an operator-supplied
 * custom path.
 */
export function isDefaultPayloadDir(payloadDir) {
  return resolve(payloadDir) === resolve(DEFAULT_PAYLOAD_DIR);
}

/** Build (seal) and publish a release from the environment configuration. */
export async function buildAndPublishRelease({
  releasesRoot,
  shellDir,
  payloadDir,
  sourceSha,
  cleanupPayload = false,
}) {
  try {
    if (process.env.WORKSPACE_ARTIFACT_KEY_B64) {
      throw new Error(
        "WORKSPACE_ARTIFACT_KEY_B64 is forbidden; release sealing requires canonical WORKSPACE_PUBLIC_KEY_B64",
      );
    }
    const publicKey = artifactPublicKeyFromEnv();
    const kid = artifactKidFromEnv();
    const packed = await packDirectory(payloadDir);
    const artifact = await sealPackage(packed, publicKey, kid, ARTIFACT_VERSION);
    await mkdir(releasesRoot, { recursive: true });
    return await publishRelease({
      releasesRoot,
      artifact,
      publicKeyB64: publicKey.toString("base64"),
      kidB64: kid.toString("base64"),
      sourceSha,
      shellDir,
    });
  } finally {
    // The plaintext payload must not linger after sealing, on success or
    // failure. Only done when the caller explicitly opts in (the CLI does so
    // only for the canonical default directory).
    if (cleanupPayload) {
      await rm(payloadDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}

/* c8 ignore start */
async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const args = new Map();
  for (let i = 0; i < rest.length; i += 2) {
    if (rest[i]?.startsWith("--")) args.set(rest[i].slice(2), rest[i + 1]);
  }
  const releasesRoot = resolve(args.get("root") ?? "web/workspace-releases");
  if (command === "validate") {
    const releaseId = args.get("release") ?? (await linkTarget(join(releasesRoot, CURRENT_LINK)));
    if (!releaseId) throw new Error("no release to validate");
    const { manifest } = await readRelease(releasesRoot, releaseId);
    console.log(`release ${manifest.release_id} valid`);
  } else if (command === "rollback") {
    const result = await rollbackCurrent(releasesRoot);
    console.log(`rolled back ${result.from} -> ${result.to}`);
  } else if (command === "current") {
    console.log((await linkTarget(join(releasesRoot, CURRENT_LINK))) ?? "none");
  } else if (command === "build") {
    const sourceSha = args.get("source-sha") ?? process.env.GITHUB_SHA ?? "unknown";
    const shellDir = resolve(args.get("shell") ?? "web/workspace-shell/dist");
    const payloadDir = resolve(args.get("payload") ?? DEFAULT_PAYLOAD_DIR);
    // Clean up the plaintext payload only for the canonical default directory;
    // an operator-supplied custom path is never deleted.
    const cleanupPayload = isDefaultPayloadDir(payloadDir);
    const { releaseId, manifest } = await buildAndPublishRelease({
      releasesRoot,
      shellDir,
      payloadDir,
      sourceSha,
      cleanupPayload,
    });
    console.log(`published ${releaseId} (${manifest.artifact.sha256_hex.slice(0, 12)})`);
    console.log(`manifest: ${join(releasesRoot, releaseId, MANIFEST_FILE)}`);
  } else {
    throw new Error("usage: build|validate|rollback|current --root <dir>");
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : "release command failed");
    process.exitCode = 1;
  });
}
/* c8 ignore stop */
