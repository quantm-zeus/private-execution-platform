// Reproducible generation of the vendored browser bindings for the audited
// crypto-envelope WASM wrapper (crates/crypto-envelope-wasm).

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { readFileSync, existsSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

const WASM_BINDGEN_VERSION = "0.2.128";
const WASM_BINDGEN_TRIPLE = "x86_64-unknown-linux-musl";
const WASM_BINDGEN_ASSET = `wasm-bindgen-${WASM_BINDGEN_VERSION}-${WASM_BINDGEN_TRIPLE}.tar.gz`;
const WASM_BINDGEN_SHA256 =
  "b51f0208fdff83515a787bd8ab9ac5865ed84dabb66d0c709957bb59793c645f";
const WASM_BINDGEN_URL = `https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/${WASM_BINDGEN_ASSET}`;
const TARGET = "wasm32-unknown-unknown";
const OUT_DIR = resolve("web/workspace-shell/src/wasm");

function run(cmd, args, env = process.env) {
  const result = spawnSync(cmd, args, { stdio: "inherit", env });
  if (result.status !== 0) throw new Error(`command failed: ${cmd} ${args.join(" ")}`);
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

async function fetchFile(url, dest) {
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok) throw new Error(`download failed: ${url} (${response.status})`);
  const buf = Buffer.from(await response.arrayBuffer());
  await writeFile(dest, buf);
  return dest;
}

async function findLocalCli() {
  const check = spawnSync("wasm-bindgen", ["--version"], { stdio: "pipe" });
  if (check.status === 0 && check.stdout.toString().includes(WASM_BINDGEN_VERSION)) {
    return "wasm-bindgen";
  }
  const defaultLocal = resolve(homedir(), ".local/bin/wasm-bindgen");
  if (existsSync(defaultLocal)) {
    const localCheck = spawnSync(defaultLocal, ["--version"], { stdio: "pipe" });
    if (localCheck.status === 0 && localCheck.stdout.toString().includes(WASM_BINDGEN_VERSION)) {
      return defaultLocal;
    }
  }
  return null;
}

async function ensureCli(bindingsCache) {
  const local = await findLocalCli();
  if (local) return local;

  const cliPath = join(
    bindingsCache,
    `wasm-bindgen-${WASM_BINDGEN_VERSION}-${WASM_BINDGEN_TRIPLE}`,
    "wasm-bindgen",
  );
  if (existsSync(cliPath)) return cliPath;
  const tarball = join(bindingsCache, WASM_BINDGEN_ASSET);
  await fetchFile(WASM_BINDGEN_URL, tarball);
  const digest = sha256File(tarball);
  if (digest !== WASM_BINDGEN_SHA256) {
    await rm(tarball, { force: true });
    throw new Error(`wasm-bindgen asset sha256 mismatch: ${digest}`);
  }
  run("tar", ["xzf", tarball, "-C", bindingsCache]);
  await rm(tarball, { force: true });
  return cliPath;
}

async function main() {
  const lock = readFileSync(resolve("Cargo.lock"), "utf8");
  const lockMatch = lock.match(/name = "wasm-bindgen"\nversion = "([0-9.]+)"/);
  if (!lockMatch) throw new Error("wasm-bindgen not found in Cargo.lock");
  if (lockMatch[1] !== WASM_BINDGEN_VERSION) {
    throw new Error(
      `CLI pin ${WASM_BINDGEN_VERSION} != locked wasm-bindgen ${lockMatch[1]}; update the pin to match`,
    );
  }

  const targetDir =
    process.env.CARGO_TARGET_DIR ||
    resolve(homedir(), ".cache/private-execution-target");

  run("cargo", ["build", "-p", "crypto-envelope-wasm", "--target", TARGET], {
    ...process.env,
    CARGO_TARGET_DIR: targetDir,
  });

  const crateTargetWasm = resolve(
    targetDir,
    `${TARGET}/debug/crypto_envelope_wasm.wasm`,
  );
  if (!existsSync(crateTargetWasm)) {
    throw new Error(`missing wasm artifact: ${crateTargetWasm}`);
  }

  const bindingsCache = await mkdtemp(join(tmpdir(), "wasm-bindgen-cli-"));
  try {
    const cli = await ensureCli(bindingsCache);
    if (cli !== "wasm-bindgen") {
      await chmod(cli, 0o755).catch(() => {});
    }
    await rm(OUT_DIR, { recursive: true, force: true });
    await mkdir(OUT_DIR, { recursive: true });
    run(cli, [
      "--out-dir",
      OUT_DIR,
      "--target",
      "web",
      "--out-name",
      "crypto-envelope-wasm",
      crateTargetWasm,
    ]);
    const generated = (await readdir(OUT_DIR)).sort();
    for (const expected of [
      "crypto-envelope-wasm.d.ts",
      "crypto-envelope-wasm.js",
      "crypto-envelope-wasm_bg.wasm",
      "crypto-envelope-wasm_bg.wasm.d.ts",
    ]) {
      if (!generated.includes(expected)) throw new Error(`missing generated file: ${expected}`);
    }
    console.log(
      `crypto wasm bindings generated (${sha256File(join(OUT_DIR, "crypto-envelope-wasm_bg.wasm")).slice(0, 16)}…)`,
    );
  } finally {
    await rm(bindingsCache, { recursive: true, force: true }).catch(() => {});
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
