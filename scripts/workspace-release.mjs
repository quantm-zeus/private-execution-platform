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

import { createHash } from "node:crypto";
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

/**
 * Add cache rules to the shell `_headers` **without dropping the hardened
 * security headers** the shell build ships. HTML revalidates, hashed assets are
 * immutable; the existing `/*` rule (CSP, nosniff, frame-deny, referrer policy,
 * no-store) is preserved because a release must never weaken the clear shell
 * that hosts the recovery-code input.
 */
export async function writeShellCacheHeaders(shellDir) {
  const headersPath = join(shellDir, "_headers");
  let existing = "";
  try {
    existing = await readFile(headersPath, "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const cacheRules = [
    "/index.html",
    "  Cache-Control: no-store, must-revalidate",
    "",
    "/assets/*",
    "  Cache-Control: public, max-age=31536000, immutable",
    "",
  ].join("\n");
  const base =
    existing.trim().length > 0
      ? `${existing.trimEnd()}\n\n`
      : "/*\n  Cache-Control: no-store\n\n";
  await writeFileDurable(headersPath, `${base}${cacheRules}`, { mode: 0o644 });
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
  await symlink(target, tmp);
  await rename(tmp, linkPath);
  // Make the rename durable before the caller proceeds to the paired symlink.
  await syncDirectory(parent);
}

/** Atomically point `current` at an existing validated release. */
export async function switchCurrent(releasesRoot, releaseId) {
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
 * Swap `current` and `previous` for rollback. Each symlink replacement is
 * atomic; the pair is not a single atomic operation, so a crash between the two
 * renames leaves `current` and `previous` pointing at the same valid release
 * (never a missing or half-written one).
 */
export async function rollbackCurrent(releasesRoot) {
  const currentPath = join(releasesRoot, CURRENT_LINK);
  const previousPath = join(releasesRoot, PREVIOUS_LINK);
  const current = await linkTarget(currentPath);
  const previous = await linkTarget(previousPath);
  if (!previous) throw new Error("no previous release to roll back to");
  await readRelease(releasesRoot, previous);
  await atomicSymlink(previousPath, current ?? previous);
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
  const manifest = JSON.parse(await readFile(join(releaseDir, MANIFEST_FILE), "utf8"));
  const artifact = await readFile(join(releaseDir, ARTIFACT_FILE));
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
  const shellAssetDigest = await digestDirectory(shellDir);
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
    await copyTree(shellDir, stagedShell);
    await writeShellCacheHeaders(stagedShell);
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
  // release cannot be read or the final rename fails. Wrap the whole tail in a
  // try/finally that removes staging unless it became the release directory.
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
      await switchCurrent(releasesRoot, releaseId);
      return { releaseId, manifest: existing.manifest };
    }

    await rename(staging, releaseDir);
    published = true;
    await syncDirectory(releasesRoot);
    await switchCurrent(releasesRoot, releaseId);
    return { releaseId, manifest };
  } finally {
    if (!published) {
      await rm(staging, { recursive: true, force: true }).catch(() => {});
    }
  }
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

/** Build (seal) and publish a release from the environment configuration. */
export async function buildAndPublishRelease({
  releasesRoot,
  shellDir,
  payloadDir,
  sourceSha,
}) {
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
  return publishRelease({
    releasesRoot,
    artifact,
    publicKeyB64: publicKey.toString("base64"),
    kidB64: kid.toString("base64"),
    sourceSha,
    shellDir,
  });
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
    const payloadDir = resolve(args.get("payload") ?? "web/workspace-payload/dist");
    const { releaseId, manifest } = await buildAndPublishRelease({
      releasesRoot,
      shellDir,
      payloadDir,
      sourceSha,
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
