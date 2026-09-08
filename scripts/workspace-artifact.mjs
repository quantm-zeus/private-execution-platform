import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { lstat, readdir, readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";

const CLEAR_HEADER = Buffer.from([0x4e, 0x42, 0x4c, 0x42, 0x01]);
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const MAX_FILES = 10_000;
const MAX_PATH_BYTES = 4096;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 256 * 1024 * 1024;

export function artifactKeyFromEnv(env = process.env) {
  const raw = env.WORKSPACE_ARTIFACT_KEY_B64;
  if (typeof raw !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(raw)) {
    throw new Error("workspace artifact key unavailable");
  }
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32 || key.toString("base64") !== raw) {
    key.fill(0);
    throw new Error("workspace artifact key unavailable");
  }
  return key;
}

async function walkFiles(root, dir = root) {
  const names = (await readdir(dir)).sort();
  const out = [];
  for (const name of names) {
    const full = join(dir, name);
    const stat = await lstat(full);
    if (stat.isSymbolicLink()) throw new Error("symbolic links are not allowed in artifact input");
    if (stat.isDirectory()) out.push(...await walkFiles(root, full));
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
  const count = Buffer.allocUnsafe(4); count.writeUInt32BE(files.length); chunks.push(count);
  let total = 4;
  for (const full of files) {
    const rel = relative(root, full).split(sep).join("/");
    const pathBytes = Buffer.from(rel, "utf8");
    const data = await readFile(full);
    if (!rel || rel.startsWith("../") || pathBytes.length > MAX_PATH_BYTES || data.length > MAX_FILE_BYTES) {
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

export function encryptPackage(plaintext, key) {
  if (!Buffer.isBuffer(plaintext) || plaintext.length === 0 || plaintext.length > MAX_PACKAGE_BYTES) throw new Error("invalid artifact package");
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("invalid artifact key");
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(CLEAR_HEADER);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([CLEAR_HEADER, nonce, tag, ciphertext]);
}

export function decryptArtifact(artifact, key) {
  if (!Buffer.isBuffer(artifact) || artifact.length <= CLEAR_HEADER.length + NONCE_BYTES + TAG_BYTES) throw new Error("invalid artifact");
  if (!artifact.subarray(0, CLEAR_HEADER.length).equals(CLEAR_HEADER)) throw new Error("invalid artifact");
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("invalid artifact key");
  const nonceStart = CLEAR_HEADER.length;
  const tagStart = nonceStart + NONCE_BYTES;
  const ciphertextStart = tagStart + TAG_BYTES;
  const decipher = createDecipheriv("aes-256-gcm", key, artifact.subarray(nonceStart, tagStart), { authTagLength: TAG_BYTES });
  decipher.setAAD(CLEAR_HEADER);
  decipher.setAuthTag(artifact.subarray(tagStart, ciphertextStart));
  const plaintext = Buffer.concat([decipher.update(artifact.subarray(ciphertextStart)), decipher.final()]);
  if (plaintext.length === 0 || plaintext.length > MAX_PACKAGE_BYTES) throw new Error("invalid artifact package");
  return plaintext;
}

export function unpackPackage(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4 || buffer.length > MAX_PACKAGE_BYTES) throw new Error("invalid artifact package");
  let offset = 0;
  const count = buffer.readUInt32BE(offset); offset += 4;
  if (count === 0 || count > MAX_FILES) throw new Error("invalid artifact file count");
  const files = new Map();
  for (let i = 0; i < count; i += 1) {
    if (offset + 6 > buffer.length) throw new Error("invalid artifact package");
    const pathLen = buffer.readUInt16BE(offset); const dataLen = buffer.readUInt32BE(offset + 2); offset += 6;
    if (pathLen === 0 || pathLen > MAX_PATH_BYTES || dataLen > MAX_FILE_BYTES || offset + pathLen + dataLen > buffer.length) throw new Error("invalid artifact package");
    const name = buffer.subarray(offset, offset + pathLen).toString("utf8"); offset += pathLen;
    if (!name || name.startsWith("/") || name.includes("..") || name.includes("\\") || files.has(name)) throw new Error("invalid artifact path");
    files.set(name, Buffer.from(buffer.subarray(offset, offset + dataLen))); offset += dataLen;
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
