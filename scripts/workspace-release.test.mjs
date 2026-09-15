import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, readlink, rename, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  ARTIFACT_FILE,
  CURRENT_LINK,
  MANIFEST_FILE,
  PREVIOUS_LINK,
  SHELL_DIR,
  computeReleaseManifest,
  digestDirectory,
  publishRelease,
  readRelease,
  releaseIdFor,
  rollbackCurrent,
  switchCurrent,
  sweepStaleStaging,
  validateReleaseManifest,
  writeShellCacheHeaders,
} from "./workspace-release.mjs";

const PUBLIC_KEY_B64 = Buffer.alloc(32, 7).toString("base64");
const KID = Buffer.alloc(16, 3);
const KID_B64 = KID.toString("base64");

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
  assert.equal(releaseIdFor("9a5a712deadbeef", digest), releaseIdFor("9a5a712deadbeef", digest));
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
    await writeFile(join(root, "assets", "app.js"), "c");
    const second = await digestDirectory(root);
    assert.notEqual(first, second);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("shell cache headers preserve the hardened security headers", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-"));
  try {
    await writeFile(
      join(root, "_headers"),
      [
        "/*",
        "  Cache-Control: no-store",
        "  X-Content-Type-Options: nosniff",
        "  X-Frame-Options: DENY",
        "  Referrer-Policy: no-referrer",
        "  Content-Security-Policy: default-src 'self'",
        "",
      ].join("\n"),
    );
    await writeShellCacheHeaders(root);
    const headers = await readFile(join(root, "_headers"), "utf8");
    // Hardening from the shell build must survive publication.
    assert.match(headers, /^\/\*/m);
    assert.match(headers, /Content-Security-Policy: default-src 'self'/);
    assert.match(headers, /X-Content-Type-Options: nosniff/);
    assert.match(headers, /X-Frame-Options: DENY/);
    assert.match(headers, /Referrer-Policy: no-referrer/);
    // Cache rules are appended, not substituted for the security block.
    assert.match(headers, /\/index\.html[\s\S]*no-store, must-revalidate/);
    assert.match(headers, /\/assets\/\*[\s\S]*immutable/);
    // The `/*` rule must precede the more specific overrides.
    assert.ok(headers.indexOf("/*") < headers.indexOf("/index.html"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("shell cache headers synthesize a wildcard rule when none shipped", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-headers-synth-"));
  try {
    await writeShellCacheHeaders(root);
    const headers = await readFile(join(root, "_headers"), "utf8");
    assert.match(headers, /^\/\*/m);
    assert.match(headers, /\/index\.html[\s\S]*no-store/);
    assert.match(headers, /\/assets\/\*[\s\S]*immutable/);
  } finally {
    await rm(root, { recursive: true, force: true });
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

test("switching to an unpublished release refuses", async () => {
  const root = await mkdtemp(join(tmpdir(), "release-switch-"));
  try {
    await assert.rejects(switchCurrent(root, "missing-release"));
    // A canonical but absent id reaches the read and fails closed too.
    await assert.rejects(switchCurrent(root, "abcdef012345-abcdef012345"));
  } finally {
    await rm(root, { recursive: true, force: true });
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
