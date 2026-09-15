import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, lstat, open, readFile, readdir, rename, rm } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import {
  artifactKidFromEnv,
  artifactPublicKeyFromEnv,
  packDirectory,
  sealPackage,
} from "./workspace-artifact.mjs";

const dist = resolve("web/workspace-payload/dist");
const outDir = resolve("web/workspace-artifact");
const outFile = resolve(outDir, "blob.bin");

/** Only temp files older than this are swept; a fresh write is never disturbed. */
export const ARTIFACT_TEMP_MAX_AGE_MS = 60 * 60 * 1000;

/**
 * Best-effort sweep of `.<basename>.*.tmp` files leaked by a hard kill. Only
 * regular files older than `maxAgeMs` are removed, so a concurrent writer's
 * fresh temp file is preserved.
 */
export async function sweepStaleArtifactTemps(
  destination,
  nowMs = Date.now(),
  maxAgeMs = ARTIFACT_TEMP_MAX_AGE_MS,
) {
  const dir = dirname(destination);
  const prefix = `.${basename(destination)}.`;
  let names;
  try {
    names = await readdir(dir);
  } catch {
    return 0;
  }
  let swept = 0;
  for (const name of names) {
    if (!name.startsWith(prefix) || !name.endsWith(".tmp")) continue;
    const full = join(dir, name);
    try {
      const info = await lstat(full);
      if (!info.isFile()) continue;
      if (nowMs - info.mtimeMs < maxAgeMs) continue;
      await rm(full, { force: true });
      swept += 1;
    } catch {
      // A concurrent writer may have consumed it; ignore.
    }
  }
  return swept;
}

/** Best-effort directory fsync so an atomic rename is durable after power loss. */
async function syncDirectory(path) {
  let handle;
  try {
    handle = await open(path, "r");
    await handle.sync();
  } catch {
    // Directory fsync is not supported on every platform/filesystem; ignore.
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

/**
 * Publish the live artifact atomically: write to a same-directory temp file
 * (mode 0600), fsync it, re-read and verify exact length and SHA-256, then
 * rename over the destination. The previous good artifact is only ever
 * replaced by a complete, verified file; on any failure only the temp file is
 * removed and the destination is left untouched.
 */
export async function writeArtifactAtomically(destination, artifact) {
  const dir = dirname(destination);
  await mkdir(dir, { recursive: true });
  // Recover disk space leaked by a previous hard kill before adding a new temp
  // file. Age-bounded so a concurrent writer's fresh temp is never removed.
  await sweepStaleArtifactTemps(destination);
  const temp = join(
    dir,
    `.${basename(destination)}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`,
  );
  const expectedDigest = createHash("sha256").update(artifact).digest("hex");
  try {
    const handle = await open(temp, "wx", 0o600);
    try {
      await handle.writeFile(artifact);
      await handle.sync();
    } finally {
      await handle.close();
    }
    const onDisk = await readFile(temp);
    if (onDisk.length !== artifact.length) throw new Error("artifact write failed");
    if (createHash("sha256").update(onDisk).digest("hex") !== expectedDigest) {
      throw new Error("artifact write failed");
    }
    await rename(temp, destination);
  } catch (error) {
    // Remove only the temp file; the previously published artifact stays live.
    await rm(temp, { force: true }).catch(() => {});
    throw error;
  }
  await syncDirectory(dir);
}

export async function main() {
  let publicKey;
  let kid;
  try {
    if (process.env.WORKSPACE_ARTIFACT_KEY_B64) {
      throw new Error(
        "WORKSPACE_ARTIFACT_KEY_B64 is forbidden; artifact sealing requires canonical 32-byte WORKSPACE_PUBLIC_KEY_B64",
      );
    }
    publicKey = artifactPublicKeyFromEnv();
    kid = artifactKidFromEnv();

    const build = spawnSync("pnpm", ["--filter", "@evergreen/workspace-payload", "build"], {
      stdio: "inherit",
    });
    if (build.status !== 0) throw new Error("workspace payload build failed");

    const packed = await packDirectory(dist);
    const artifact = await sealPackage(packed, publicKey, kid);

    await writeArtifactAtomically(outFile, artifact);
    console.log("encrypted workspace artifact created");
  } catch (error) {
    console.error(error instanceof Error ? error.message : "workspace artifact build failed");
    process.exitCode = 1;
  } finally {
    delete process.env.WORKSPACE_PUBLIC_KEY_B64;
    delete process.env.WORKSPACE_ARTIFACT_KID_B64;
    delete process.env.WORKSPACE_ARTIFACT_KEY_B64;
    await rm(dist, { recursive: true, force: true }).catch(() => {});
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
