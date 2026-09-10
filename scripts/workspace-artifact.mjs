import { spawnSync } from "node:child_process";
import { lstat, readdir, readFile, writeFile, mkdir, rm, mkdtemp } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";

export const ARTIFACT_VERSION = 1;
export const KID_BYTES = 16;
export const PUBLIC_KEY_BYTES = 32;
export const UNLOCK_SECRET_BYTES = 32;
export const ENCAPSULATED_KEY_BYTES = 32;
export const TAG_BYTES = 16;
export const ARTIFACT_HEADER_BYTES = 1 + KID_BYTES + ENCAPSULATED_KEY_BYTES; // 49
export const MIN_ARTIFACT_BYTES = ARTIFACT_HEADER_BYTES + TAG_BYTES; // 65
export const MAX_FILES = 10_000;
export const MAX_PATH_BYTES = 4096;
export const MAX_FILE_BYTES = 64 * 1024 * 1024;
export const MAX_PACKAGE_BYTES = 256 * 1024 * 1024;

export function artifactPublicKeyFromEnv(env = process.env) {
  if (env.WORKSPACE_ARTIFACT_KEY_B64) {
    throw new Error(
      "WORKSPACE_ARTIFACT_KEY_B64 is forbidden; artifact sealing requires canonical 32-byte WORKSPACE_PUBLIC_KEY_B64",
    );
  }
  const raw = env.WORKSPACE_PUBLIC_KEY_B64;
  if (typeof raw !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(raw)) {
    throw new Error("workspace public key unavailable or invalid base64");
  }
  const key = Buffer.from(raw, "base64");
  if (key.length !== PUBLIC_KEY_BYTES || key.toString("base64") !== raw) {
    throw new Error("workspace public key must be exactly 32 bytes");
  }
  if (key.every((b) => b === 0)) {
    throw new Error("all-zero workspace public key rejected");
  }
  return key;
}

export function artifactKidFromEnv(env = process.env) {
  const raw = env.WORKSPACE_ARTIFACT_KID_B64;
  if (!raw) {
    return Buffer.alloc(KID_BYTES);
  }
  if (typeof raw !== "string" || !/^[A-Za-z0-9+/]{22}==$/.test(raw)) {
    throw new Error("workspace kid invalid base64");
  }
  const kid = Buffer.from(raw, "base64");
  if (kid.length !== KID_BYTES || kid.toString("base64") !== raw) {
    throw new Error("workspace kid must be exactly 16 bytes");
  }
  return kid;
}

export function unlockSecretFromEnv(env = process.env) {
  const raw = env.WORKSPACE_UNLOCK_SECRET_B64;
  if (typeof raw !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(raw)) {
    throw new Error("workspace unlock secret unavailable or invalid base64");
  }
  const secret = Buffer.from(raw, "base64");
  if (secret.length !== UNLOCK_SECRET_BYTES || secret.toString("base64") !== raw) {
    secret.fill(0);
    throw new Error("workspace unlock secret must be exactly 32 bytes");
  }
  if (secret.every((b) => b === 0)) {
    secret.fill(0);
    throw new Error("all-zero workspace unlock secret rejected");
  }
  return secret;
}

function resolveBin(binName) {
  const targetDir =
    process.env.CARGO_TARGET_DIR ||
    resolve(homedir(), ".cache/private-execution-target");
  const directPath = resolve(targetDir, "debug", binName);
  return { directPath, targetDir };
}

function runRustCli(binName, args) {
  const { directPath } = resolveBin(binName);
  let result = spawnSync(directPath, args, { stdio: "pipe" });
  if (result.status !== 0 && result.error?.code === "ENOENT") {
    // Fall back to cargo run
    result = spawnSync(
      "cargo",
      ["run", "--quiet", "-p", "crypto-envelope", "--bin", binName, "--", ...args],
      { stdio: "pipe" },
    );
  }
  if (result.status !== 0) {
    const err = result.stderr ? result.stderr.toString() : "cli failed";
    throw new Error(`${binName} failed: ${err}`);
  }
}

export function derivePublicKey(
  unlockSecret,
  kid = Buffer.alloc(KID_BYTES),
  version = ARTIFACT_VERSION,
) {
  if (!Buffer.isBuffer(unlockSecret) || unlockSecret.length !== UNLOCK_SECRET_BYTES) {
    throw new Error("invalid unlock secret");
  }
  if (!Buffer.isBuffer(kid) || kid.length !== KID_BYTES) {
    throw new Error("invalid kid");
  }
  const { directPath } = resolveBin("derive-public-key");
  const args = [
    "--unlock-secret-b64",
    unlockSecret.toString("base64"),
    "--kid-b64",
    kid.toString("base64"),
    "--version",
    String(version),
  ];
  let result = spawnSync(directPath, args, { stdio: "pipe" });
  if (result.status !== 0 && result.error?.code === "ENOENT") {
    result = spawnSync(
      "cargo",
      ["run", "--quiet", "-p", "crypto-envelope", "--bin", "derive-public-key", "--", ...args],
      { stdio: "pipe" },
    );
  }
  if (result.status !== 0) {
    const err = result.stderr ? result.stderr.toString() : "derive-public-key failed";
    throw new Error(`derive-public-key failed: ${err}`);
  }
  const outB64 = result.stdout.toString().trim();
  const pk = Buffer.from(outB64, "base64");
  if (pk.length !== PUBLIC_KEY_BYTES) {
    throw new Error("derived public key invalid size");
  }
  return pk;
}

export async function sealPackage(
  plaintext,
  publicKey,
  kid = Buffer.alloc(KID_BYTES),
  version = ARTIFACT_VERSION,
) {
  if (!Buffer.isBuffer(plaintext) || plaintext.length === 0 || plaintext.length > MAX_PACKAGE_BYTES) {
    throw new Error("invalid artifact package");
  }
  if (!Buffer.isBuffer(publicKey) || publicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error("invalid recipient public key");
  }
  if (!Buffer.isBuffer(kid) || kid.length !== KID_BYTES) {
    throw new Error("invalid kid");
  }
  if (version !== ARTIFACT_VERSION) {
    throw new Error("unsupported artifact version");
  }

  const tempDir = await mkdtemp(join(tmpdir(), "artifact-seal-"));
  const inPath = join(tempDir, "input.bin");
  const outPath = join(tempDir, "output.bin");
  try {
    await writeFile(inPath, plaintext);
    runRustCli("seal-artifact", [
      "--public-key-b64",
      publicKey.toString("base64"),
      "--kid-b64",
      kid.toString("base64"),
      "--version",
      String(version),
      "--input",
      inPath,
      "--output",
      outPath,
    ]);
    const sealed = await readFile(outPath);
    if (sealed.length < MIN_ARTIFACT_BYTES) {
      throw new Error("sealed artifact invalid size");
    }
    return sealed;
  } finally {
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}

export async function decryptArtifact(
  artifact,
  unlockSecret,
  kid = Buffer.alloc(KID_BYTES),
  version = ARTIFACT_VERSION,
) {
  if (!Buffer.isBuffer(artifact) || artifact.length < MIN_ARTIFACT_BYTES) {
    throw new Error("invalid artifact");
  }
  if (!Buffer.isBuffer(unlockSecret) || unlockSecret.length !== UNLOCK_SECRET_BYTES) {
    throw new Error("invalid unlock secret");
  }
  if (!Buffer.isBuffer(kid) || kid.length !== KID_BYTES) {
    throw new Error("invalid kid");
  }
  if (version !== ARTIFACT_VERSION) {
    throw new Error("unsupported artifact version");
  }

  const tempDir = await mkdtemp(join(tmpdir(), "artifact-decrypt-"));
  const inPath = join(tempDir, "input.bin");
  const outPath = join(tempDir, "output.bin");
  try {
    await writeFile(inPath, artifact);
    runRustCli("decrypt-artifact", [
      "--unlock-secret-b64",
      unlockSecret.toString("base64"),
      "--kid-b64",
      kid.toString("base64"),
      "--version",
      String(version),
      "--input",
      inPath,
      "--output",
      outPath,
    ]);
    const plaintext = await readFile(outPath);
    if (plaintext.length === 0 || plaintext.length > MAX_PACKAGE_BYTES) {
      throw new Error("invalid artifact package");
    }
    return plaintext;
  } finally {
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}

async function walkFiles(root, dir = root) {
  const names = (await readdir(dir)).sort();
  const out = [];
  for (const name of names) {
    const full = join(dir, name);
    const stat = await lstat(full);
    if (stat.isSymbolicLink()) throw new Error("symbolic links are not allowed in artifact input");
    if (stat.isDirectory()) out.push(...(await walkFiles(root, full)));
    else if (stat.isFile()) out.push(full);
    else throw new Error("unsupported artifact input entry");
  }
  return out;
}

export async function packDirectory(rootDir) {
  const root = resolve(rootDir);
  const files = await walkFiles(root);
  if (files.length === 0 || files.length > MAX_FILES) throw new Error("invalid artifact file count");
  const chunks = [];
  const count = Buffer.allocUnsafe(4);
  count.writeUInt32BE(files.length);
  chunks.push(count);
  let total = 4;
  for (const full of files) {
    const rel = relative(root, full).split(sep).join("/");
    const pathBytes = Buffer.from(rel, "utf8");
    const data = await readFile(full);
    if (
      !rel ||
      rel.startsWith("../") ||
      pathBytes.length > MAX_PATH_BYTES ||
      data.length > MAX_FILE_BYTES
    ) {
      throw new Error("invalid artifact file");
    }
    const meta = Buffer.allocUnsafe(6);
    meta.writeUInt16BE(pathBytes.length, 0);
    meta.writeUInt32BE(data.length, 2);
    chunks.push(meta, pathBytes, data);
    total += meta.length + pathBytes.length + data.length;
    if (total > MAX_PACKAGE_BYTES) throw new Error("artifact package too large");
  }
  return Buffer.concat(chunks, total);
}

export function unpackPackage(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4 || buffer.length > MAX_PACKAGE_BYTES) {
    throw new Error("invalid artifact package");
  }
  let offset = 0;
  const count = buffer.readUInt32BE(offset);
  offset += 4;
  if (count === 0 || count > MAX_FILES) throw new Error("invalid artifact file count");
  const files = new Map();
  for (let i = 0; i < count; i += 1) {
    if (offset + 6 > buffer.length) throw new Error("invalid artifact package");
    const pathLen = buffer.readUInt16BE(offset);
    const dataLen = buffer.readUInt32BE(offset + 2);
    offset += 6;
    if (
      pathLen === 0 ||
      pathLen > MAX_PATH_BYTES ||
      dataLen > MAX_FILE_BYTES ||
      offset + pathLen + dataLen > buffer.length
    ) {
      throw new Error("invalid artifact package");
    }
    const name = buffer.subarray(offset, offset + pathLen).toString("utf8");
    offset += pathLen;
    if (!name || name.startsWith("/") || name.includes("..") || name.includes("\\") || files.has(name)) {
      throw new Error("invalid artifact path");
    }
    files.set(name, Buffer.from(buffer.subarray(offset, offset + dataLen)));
    offset += dataLen;
  }
  if (offset !== buffer.length) throw new Error("invalid artifact package");
  return files;
}

export async function writeUnpacked(files, outputDir) {
  for (const [name, data] of files) {
    const target = resolve(outputDir, name);
    const root = resolve(outputDir) + sep;
    if (!target.startsWith(root)) throw new Error("invalid artifact path");
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, data);
  }
}
