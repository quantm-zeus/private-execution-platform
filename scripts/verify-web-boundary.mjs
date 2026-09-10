import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { decryptArtifactFile } from "./decrypt-workspace-artifact.mjs";
import {
  ARTIFACT_HEADER_BYTES,
  ARTIFACT_VERSION,
  derivePublicKey,
  packDirectory,
} from "./workspace-artifact.mjs";

function run(args, env = process.env) {
  const result = spawnSync("pnpm", args, { stdio: "inherit", env });
  if (result.status !== 0) throw new Error(`command failed: pnpm ${args.join(" ")}`);
}

async function filesUnder(root) {
  const out = [];
  async function walk(dir) {
    for (const name of (await readdir(dir)).sort()) {
      const p = join(dir, name);
      const s = await stat(p);
      if (s.isDirectory()) await walk(p);
      else if (s.isFile()) out.push(p);
    }
  }
  await walk(root);
  return out;
}

function digest(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

const publicOut = resolve("web/public/.output");
const workspaceDist = resolve("web/workspace/dist");
const artifactPath = resolve("web/workspace-artifact/blob.bin");
const forbidden = [
  "@evergreen/workspace",
  "web/workspace",
  "swap",
  "wallet",
  "jupiter",
  "raydium",
  "uniswap",
  "limit_order",
  "privy",
  "trading-core",
  "/v1/stream",
];

let unlockSecret;
let temp;

try {
  // 1. Verify public build does not leak private terms or source maps
  run(["build:public"]);
  for (const path of await filesUnder(publicOut)) {
    if (path.endsWith(".map")) throw new Error("public source map detected");
    if (/\.(?:m?js|html|css|json)$/i.test(path)) {
      const text = (await readFile(path, "utf8")).toLowerCase();
      for (const term of forbidden) {
        if (text.includes(term.toLowerCase())) {
          throw new Error(`public bundle privacy term detected: ${term}`);
        }
      }
    }
  }

  // 2. Build workspace plaintext to establish expected package digest
  run(["build:workspace"]);
  const expected = await packDirectory(workspaceDist);
  const expectedHash = digest(expected);

  // 3. Generate high-entropy 32-byte unlock secret and 16-byte kid
  unlockSecret = randomBytes(32);
  const kid = randomBytes(16);
  const publicKey = derivePublicKey(unlockSecret, kid, ARTIFACT_VERSION);

  // 4. Verify WORKSPACE_ARTIFACT_KEY_B64 is strictly forbidden
  const forbiddenAttempt = spawnSync("pnpm", ["build:workspace:encrypted"], {
    stdio: "pipe",
    env: {
      ...process.env,
      WORKSPACE_ARTIFACT_KEY_B64: randomBytes(32).toString("base64"),
    },
  });
  if (forbiddenAttempt.status === 0) {
    throw new Error("WORKSPACE_ARTIFACT_KEY_B64 was unexpectedly accepted by encrypted build");
  }

  // 4b. Verify missing WORKSPACE_ARTIFACT_KID_B64 is strictly rejected
  const missingKidBuildAttempt = spawnSync("pnpm", ["build:workspace:encrypted"], {
    stdio: "pipe",
    env: {
      ...process.env,
      WORKSPACE_PUBLIC_KEY_B64: publicKey.toString("base64"),
    },
  });
  if (missingKidBuildAttempt.status === 0) {
    throw new Error("missing WORKSPACE_ARTIFACT_KID_B64 was unexpectedly accepted by encrypted build");
  }

  // 4c. Verify all-zero WORKSPACE_ARTIFACT_KID_B64 is strictly rejected
  const zeroKidBuildAttempt = spawnSync("pnpm", ["build:workspace:encrypted"], {
    stdio: "pipe",
    env: {
      ...process.env,
      WORKSPACE_PUBLIC_KEY_B64: publicKey.toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: Buffer.alloc(16).toString("base64"),
    },
  });
  if (zeroKidBuildAttempt.status === 0) {
    throw new Error("all-zero WORKSPACE_ARTIFACT_KID_B64 was unexpectedly accepted by encrypted build");
  }

  // 5. Build encrypted workspace artifact with ONLY public key and kid
  run(["build:workspace:encrypted"], {
    ...process.env,
    WORKSPACE_PUBLIC_KEY_B64: publicKey.toString("base64"),
    WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
  });

  // 6. Verify plaintext build output was cleaned up
  try {
    await stat(workspaceDist);
    throw new Error("plaintext workspace build remains");
  } catch (e) {
    if (e?.code !== "ENOENT") throw e;
  }

  // 7. Verify sealed artifact
  const raw = await readFile(artifactPath);

  // Scan artifact for plaintext leaks
  for (const clear of ["index.html", "Workspace", "workspace"]) {
    if (raw.includes(Buffer.from(clear))) {
      throw new Error(`artifact leaks plaintext metadata: ${clear}`);
    }
  }

  // Scan artifact for raw secret key material
  if (raw.includes(unlockSecret)) {
    throw new Error("artifact contains raw unlock secret");
  }

  // Validate envelope structure
  if (raw.length <= ARTIFACT_HEADER_BYTES) {
    throw new Error("artifact smaller than minimum envelope header");
  }
  if (raw[0] !== ARTIFACT_VERSION) {
    throw new Error(`artifact has invalid version byte: ${raw[0]}`);
  }
  if (!raw.subarray(1, 17).equals(kid)) {
    throw new Error("artifact header kid mismatch");
  }

  // 8. Decrypt with valid unlock secret & kid
  const { plaintext } = await decryptArtifactFile(artifactPath, {
    WORKSPACE_UNLOCK_SECRET_B64: unlockSecret.toString("base64"),
    WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
  });
  if (digest(plaintext) !== expectedHash) {
    throw new Error("artifact roundtrip mismatch");
  }

  // 9. Negative tests: all fail closed
  temp = await mkdtemp(join(tmpdir(), "web-boundary-test-"));

  // 9a. Tampered ciphertext
  const tamperedCt = Buffer.from(raw);
  tamperedCt[tamperedCt.length - 1] ^= 1;
  const tamperedCtPath = join(temp, "tampered-ct.bin");
  await writeFile(tamperedCtPath, tamperedCt);
  let rejected = false;
  try {
    await decryptArtifactFile(tamperedCtPath, {
      WORKSPACE_UNLOCK_SECRET_B64: unlockSecret.toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
    });
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("tampered ciphertext was accepted");

  // 9b. Tampered kid in envelope header
  const tamperedKid = Buffer.from(raw);
  tamperedKid[1] ^= 1;
  const tamperedKidPath = join(temp, "tampered-kid.bin");
  await writeFile(tamperedKidPath, tamperedKid);
  rejected = false;
  try {
    await decryptArtifactFile(tamperedKidPath, {
      WORKSPACE_UNLOCK_SECRET_B64: unlockSecret.toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
    });
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("tampered kid was accepted");

  // 9c. Tampered version in envelope header
  const tamperedVer = Buffer.from(raw);
  tamperedVer[0] ^= 1;
  const tamperedVerPath = join(temp, "tampered-ver.bin");
  await writeFile(tamperedVerPath, tamperedVer);
  rejected = false;
  try {
    await decryptArtifactFile(tamperedVerPath, {
      WORKSPACE_UNLOCK_SECRET_B64: unlockSecret.toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
    });
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("tampered version was accepted");

  // 9d. Wrong unlock secret (fails closed)
  const wrongSecret = Buffer.from(unlockSecret);
  wrongSecret[31] ^= 0xff;
  rejected = false;
  try {
    await decryptArtifactFile(artifactPath, {
      WORKSPACE_UNLOCK_SECRET_B64: wrongSecret.toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
    });
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("wrong unlock secret was accepted");

  // 9e. Wrong kid in context (fails closed)
  const wrongKid = Buffer.from(kid);
  wrongKid[0] ^= 1;
  rejected = false;
  try {
    await decryptArtifactFile(artifactPath, {
      WORKSPACE_UNLOCK_SECRET_B64: unlockSecret.toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: wrongKid.toString("base64"),
    });
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("wrong kid in context was accepted");

  // 9f. Missing kid in decrypt env (fails closed)
  rejected = false;
  try {
    await decryptArtifactFile(artifactPath, {
      WORKSPACE_UNLOCK_SECRET_B64: unlockSecret.toString("base64"),
    });
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("missing kid in decrypt env was accepted");

  // 9g. All-zero kid in decrypt env (fails closed)
  rejected = false;
  try {
    await decryptArtifactFile(artifactPath, {
      WORKSPACE_UNLOCK_SECRET_B64: unlockSecret.toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: Buffer.alloc(16).toString("base64"),
    });
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("all-zero kid in decrypt env was accepted");

  // 9h. Preflight metadata: empty input file fails closed in seal-artifact CLI
  const emptyFile = join(temp, "empty-input.bin");
  await writeFile(emptyFile, Buffer.alloc(0));
  const sealEmptyAttempt = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "seal-artifact", "--",
    "--public-key-b64", publicKey.toString("base64"),
    "--kid-b64", kid.toString("base64"),
    "--input", emptyFile,
    "--output", join(temp, "empty-out.bin"),
  ], { stdio: "pipe" });
  if (sealEmptyAttempt.status === 0) {
    throw new Error("empty input file was unexpectedly accepted by seal-artifact");
  }

  // 9i. Preflight metadata: truncated artifact file (< 65 bytes) fails closed in decrypt-artifact CLI
  const truncFile = join(temp, "trunc-input.bin");
  await writeFile(truncFile, Buffer.alloc(64));
  const decryptTruncAttempt = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "decrypt-artifact", "--",
    "--unlock-secret-b64", unlockSecret.toString("base64"),
    "--kid-b64", kid.toString("base64"),
    "--input", truncFile,
    "--output", join(temp, "trunc-out.bin"),
  ], { stdio: "pipe" });
  if (decryptTruncAttempt.status === 0) {
    throw new Error("truncated artifact was unexpectedly accepted by decrypt-artifact");
  }

  // 9j. Missing kid fails closed on CLI seal-artifact
  const missingKidSeal = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "seal-artifact", "--",
    "--public-key-b64", publicKey.toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe", env: { PATH: process.env.PATH } });
  if (missingKidSeal.status === 0) {
    throw new Error("missing kid was unexpectedly accepted by seal-artifact CLI");
  }

  // 9k. All-zero kid fails closed on CLI seal-artifact
  const zeroKidSeal = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "seal-artifact", "--",
    "--public-key-b64", publicKey.toString("base64"),
    "--kid-b64", Buffer.alloc(16).toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe", env: { PATH: process.env.PATH } });
  if (zeroKidSeal.status === 0) {
    throw new Error("all-zero kid was unexpectedly accepted by seal-artifact CLI");
  }

  // 9l. Missing kid fails closed on CLI decrypt-artifact
  const missingKidDecrypt = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "decrypt-artifact", "--",
    "--unlock-secret-b64", unlockSecret.toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe", env: { PATH: process.env.PATH } });
  if (missingKidDecrypt.status === 0) {
    throw new Error("missing kid was unexpectedly accepted by decrypt-artifact CLI");
  }

  // 9m. All-zero kid fails closed on CLI decrypt-artifact
  const zeroKidDecrypt = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "decrypt-artifact", "--",
    "--unlock-secret-b64", unlockSecret.toString("base64"),
    "--kid-b64", Buffer.alloc(16).toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe", env: { PATH: process.env.PATH } });
  if (zeroKidDecrypt.status === 0) {
    throw new Error("all-zero kid was unexpectedly accepted by decrypt-artifact CLI");
  }

  console.log("web boundary verification passed");
} finally {
  if (unlockSecret) unlockSecret.fill(0);
  delete process.env.WORKSPACE_PUBLIC_KEY_B64;
  delete process.env.WORKSPACE_ARTIFACT_KID_B64;
  delete process.env.WORKSPACE_UNLOCK_SECRET_B64;
  delete process.env.WORKSPACE_ARTIFACT_KEY_B64;
  if (temp) await rm(temp, { recursive: true, force: true }).catch(() => {});
  await rm(workspaceDist, { recursive: true, force: true }).catch(() => {});
}
