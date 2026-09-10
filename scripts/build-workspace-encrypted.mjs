import { spawnSync } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  artifactKidFromEnv,
  artifactPublicKeyFromEnv,
  packDirectory,
  sealPackage,
} from "./workspace-artifact.mjs";

const dist = resolve("web/workspace/dist");
const outDir = resolve("web/workspace-artifact");
const outFile = resolve(outDir, "blob.bin");

let publicKey;
let kid;
try {
  publicKey = artifactPublicKeyFromEnv();
  kid = artifactKidFromEnv();

  const build = spawnSync("pnpm", ["--filter", "@evergreen/workspace", "build"], {
    stdio: "inherit",
  });
  if (build.status !== 0) throw new Error("workspace build failed");

  const packed = await packDirectory(dist);
  const artifact = await sealPackage(packed, publicKey, kid);

  await mkdir(outDir, { recursive: true });
  await writeFile(outFile, artifact, { mode: 0o600 });

  // Read once so write failures/truncation are detected before plaintext cleanup.
  if ((await readFile(outFile)).length !== artifact.length) {
    throw new Error("artifact write failed");
  }
  console.log("encrypted workspace artifact created");
} catch (error) {
  await rm(outFile, { force: true }).catch(() => {});
  console.error(error instanceof Error ? error.message : "workspace artifact build failed");
  process.exitCode = 1;
} finally {
  delete process.env.WORKSPACE_PUBLIC_KEY_B64;
  delete process.env.WORKSPACE_ARTIFACT_KID_B64;
  delete process.env.WORKSPACE_ARTIFACT_KEY_B64;
  await rm(dist, { recursive: true, force: true }).catch(() => {});
}
