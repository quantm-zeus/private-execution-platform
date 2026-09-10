import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { decryptArtifactFile } from "./decrypt-workspace-artifact.mjs";
import {
  ARTIFACT_HEADER_BYTES,
  ARTIFACT_VERSION,
  derivePublicKey,
  packDirectory,
  unpackPackage,
  artifactPublicKeyFromEnv,
  artifactKidFromEnv,
  unlockSecretFromEnv,
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
const shellDist = resolve("web/workspace-shell/dist");
const payloadDist = resolve("web/workspace-payload/dist");
const artifactPath = resolve("web/workspace-artifact/blob.bin");

const forbiddenTradingTerms = [
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

const forbiddenStorageTerms = [
  "localStorage",
  "sessionStorage",
  "indexedDB",
  "caches",
  "document.cookie",
];

let unlockSecret;
let temp;

try {
  // =========================================================================
  // 1. Verify public build does not leak private terms or source maps
  // =========================================================================
  run(["build:public"]);
  for (const path of await filesUnder(publicOut)) {
    if (path.endsWith(".map")) throw new Error("public source map detected");
    if (/\.(?:m?js|html|css|json)$/i.test(path)) {
      const text = (await readFile(path, "utf8")).toLowerCase();
      for (const term of [
        "@evergreen/workspace-payload",
        "web/workspace-payload",
        "@evergreen/workspace",
        "web/workspace",
        ...forbiddenTradingTerms,
      ]) {
        if (text.includes(term.toLowerCase())) {
          throw new Error(`public bundle privacy term detected: ${term}`);
        }
      }
    }
  }

  // =========================================================================
  // 2. Build shell and verify delivery/build constraints fail closed
  // =========================================================================
  run(["build:workspace-shell"]);

  // 2a. Shell emits no source maps
  const shellBuiltFiles = await filesUnder(shellDist);
  for (const path of shellBuiltFiles) {
    if (path.endsWith(".map")) {
      throw new Error(`shell emitted forbidden source map: ${path}`);
    }
  }

  // 2b. Shell index.html enforces strict own-origin CSP, no-store, nosniff
  const shellHtmlPath = join(shellDist, "index.html");
  const shellHtml = await readFile(shellHtmlPath, "utf8");

  // Verify CSP meta tag
  const cspMatch = shellHtml.match(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i);
  if (!cspMatch) {
    throw new Error("workspace-shell index.html missing Content-Security-Policy meta tag");
  }
  const cspContent = cspMatch[1];
  if (!cspContent.includes("default-src 'self'")) {
    throw new Error("shell CSP missing default-src 'self'");
  }
  if (!cspContent.includes("object-src 'none'")) {
    throw new Error("shell CSP missing object-src 'none'");
  }
  if (!cspContent.includes("base-uri 'none'")) {
    throw new Error("shell CSP missing base-uri 'none'");
  }
  if (!cspContent.includes("connect-src 'self'")) {
    throw new Error("shell CSP missing connect-src 'self'");
  }
  // No external hosts or unconstrained origins
  if (/https?:\/\//i.test(cspContent) || cspContent.includes("*")) {
    throw new Error(`shell CSP contains non-own-origin or wildcard directive: ${cspContent}`);
  }

  // Verify no-store meta tag
  const cacheControlMatch = shellHtml.match(/<meta\s+http-equiv="Cache-Control"\s+content="([^"]+)"/i);
  if (!cacheControlMatch || !cacheControlMatch[1].includes("no-store")) {
    throw new Error("workspace-shell index.html missing Cache-Control: no-store meta tag");
  }

  // Verify nosniff meta tag
  const nosniffMatch = shellHtml.match(/<meta\s+http-equiv="X-Content-Type-Options"\s+content="nosniff"/i);
  if (!nosniffMatch) {
    throw new Error("workspace-shell index.html missing X-Content-Type-Options: nosniff meta tag");
  }

  // 2c. Shell Vite config defines fail-closed server & preview headers
  const shellViteConfig = await readFile(resolve("web/workspace-shell/vite.config.ts"), "utf8");
  if (!shellViteConfig.includes('"Cache-Control": "no-store"') || !shellViteConfig.includes('"X-Content-Type-Options": "nosniff"')) {
    throw new Error("workspace-shell vite.config.ts missing fail-closed security headers");
  }
  if (!shellViteConfig.includes("sourcemap: false")) {
    throw new Error("workspace-shell vite.config.ts must enforce sourcemap: false");
  }

  // 2d. Shell code & bundle contains no third-party network calls, analytics, or persistent storage
  const shellSourceFiles = [
    resolve("web/workspace-shell/src/index.tsx"),
    resolve("web/workspace-shell/src/wasm-loader.ts"),
    shellHtmlPath,
  ];
  for (const p of shellBuiltFiles) {
    if (/\.(?:m?js|html|css)$/i.test(p)) shellSourceFiles.push(p);
  }
  for (const path of shellSourceFiles) {
    const text = await readFile(path, "utf8");
    // No persistent browser storage
    for (const term of forbiddenStorageTerms) {
      if (text.includes(term)) {
        throw new Error(`shell file ${path} references forbidden storage API: ${term}`);
      }
    }
    // No private trading semantics
    for (const term of forbiddenTradingTerms) {
      if (text.toLowerCase().includes(term.toLowerCase())) {
        throw new Error(`shell file ${path} encodes private trading semantic: ${term}`);
      }
    }
    // No external network endpoints / analytics
    for (const match of text.matchAll(/https?:\/\/[^"'`\s)]+/g)) {
      const url = match[0];
      if (
        url.startsWith("https://localhost") ||
        url.startsWith("http://localhost") ||
        url.startsWith("http://www.w3.org/") ||
        url.startsWith("https://www.w3.org/")
      ) {
        continue;
      }
      throw new Error(`shell file ${path} contains non-own-origin URL: ${url}`);
    }
    for (const tracker of ["google-analytics", "googletagmanager", "mixpanel", "segment", "sentry"]) {
      if (text.toLowerCase().includes(tracker)) {
        throw new Error(`shell file ${path} references external tracker: ${tracker}`);
      }
    }
  }

  // =========================================================================
  // 3. Shell / payload circular-bootstrap prevention
  // =========================================================================
  // 3a. Shell source must NOT import workspace-payload
  const shellIndexSrc = await readFile(resolve("web/workspace-shell/src/index.tsx"), "utf8");
  const shellLoaderSrc = await readFile(resolve("web/workspace-shell/src/wasm-loader.ts"), "utf8");
  for (const [name, content] of [["index.tsx", shellIndexSrc], ["wasm-loader.ts", shellLoaderSrc]]) {
    if (content.includes("workspace-payload") || content.includes("@evergreen/workspace-payload")) {
      throw new Error(`circular bootstrap: shell ${name} imports private payload`);
    }
  }
  // 3b. Shell bundle must NOT contain payload package identity
  for (const path of shellBuiltFiles) {
    if (/\.m?js$/i.test(path)) {
      const content = await readFile(path, "utf8");
      if (content.includes("@evergreen/workspace-payload") || content.includes("workspace-payload")) {
        throw new Error(`circular bootstrap: shell bundle ${path} includes private payload module`);
      }
    }
  }
  // 3c. Payload source must NOT import workspace-shell
  const payloadIndexSrc = await readFile(resolve("web/workspace-payload/src/index.tsx"), "utf8");
  if (payloadIndexSrc.includes("workspace-shell") || payloadIndexSrc.includes("@evergreen/workspace-shell")) {
    throw new Error("circular bootstrap: payload imports workspace shell");
  }

  // =========================================================================
  // 4. Audited WASM binding loading & API boundary retention (Slice A contract)
  // =========================================================================
  const wasmGluePath = resolve("web/workspace-shell/src/wasm/crypto-envelope-wasm.js");
  const wasmBinaryPath = resolve("web/workspace-shell/src/wasm/crypto-envelope-wasm_bg.wasm");
  const wasmBytes = await readFile(wasmBinaryPath);
  if (wasmBytes.length < 100_000) {
    throw new Error("vendored wasm binary is invalid or truncated");
  }

  const wasmModule = await import(pathToFileURL(wasmGluePath).href);
  await wasmModule.default({ module_or_path: wasmBytes });

  // Verify Slice A contract: seal_workspace_artifact must NOT be exported
  if ("seal_workspace_artifact" in wasmModule || "seal_artifact" in wasmModule) {
    throw new Error("Slice A violation: seal function re-exported to JS wasm bindings");
  }
  if (!wasmModule.WasmWorkspaceKey || !wasmModule.WasmOffer || !wasmModule.WasmInitiatorSession) {
    throw new Error("audited wasm bindings missing required exported classes");
  }

  // Executable wasm check: derive key in memory via wasm
  const testSecret = randomBytes(32);
  const testKid = randomBytes(16);
  const testKey = new wasmModule.WasmWorkspaceKey(testSecret, ARTIFACT_VERSION, testKid);
  const wasmDerivedPk = Buffer.from(testKey.public_key());
  const rustCliDerivedPk = derivePublicKey(testSecret, testKid, ARTIFACT_VERSION);
  if (!wasmDerivedPk.equals(rustCliDerivedPk)) {
    throw new Error("wasm key derivation does not match Rust CLI derive-public-key");
  }
  testKey.free();

  // =========================================================================
  // 5. Forbidden key rejection across build, verification, and helpers
  // =========================================================================
  // 5a. WORKSPACE_ARTIFACT_KEY_B64 forbidden in build:workspace:encrypted
  const forbiddenBuildAttempt = spawnSync("pnpm", ["build:workspace:encrypted"], {
    stdio: "pipe",
    env: {
      ...process.env,
      WORKSPACE_ARTIFACT_KEY_B64: randomBytes(32).toString("base64"),
    },
  });
  if (forbiddenBuildAttempt.status === 0) {
    throw new Error("WORKSPACE_ARTIFACT_KEY_B64 was unexpectedly accepted by encrypted build");
  }

  // 5b. WORKSPACE_ARTIFACT_KEY_B64 forbidden in artifactPublicKeyFromEnv
  let forbiddenRejected = false;
  try {
    artifactPublicKeyFromEnv({ WORKSPACE_ARTIFACT_KEY_B64: randomBytes(32).toString("base64") });
  } catch {
    forbiddenRejected = true;
  }
  if (!forbiddenRejected) {
    throw new Error("WORKSPACE_ARTIFACT_KEY_B64 was accepted by artifactPublicKeyFromEnv");
  }

  // 5c. WORKSPACE_ARTIFACT_KEY_B64 forbidden in artifactKidFromEnv
  forbiddenRejected = false;
  try {
    artifactKidFromEnv({ WORKSPACE_ARTIFACT_KEY_B64: randomBytes(32).toString("base64") });
  } catch {
    forbiddenRejected = true;
  }
  if (!forbiddenRejected) {
    throw new Error("WORKSPACE_ARTIFACT_KEY_B64 was accepted by artifactKidFromEnv");
  }

  // 5d. WORKSPACE_ARTIFACT_KEY_B64 forbidden in unlockSecretFromEnv
  forbiddenRejected = false;
  try {
    unlockSecretFromEnv({ WORKSPACE_ARTIFACT_KEY_B64: randomBytes(32).toString("base64") });
  } catch {
    forbiddenRejected = true;
  }
  if (!forbiddenRejected) {
    throw new Error("WORKSPACE_ARTIFACT_KEY_B64 was accepted by unlockSecretFromEnv");
  }

  // =========================================================================
  // 6. Strict validation on required WORKSPACE_PUBLIC_KEY_B64 and KID
  // =========================================================================
  unlockSecret = randomBytes(32);
  const kid = randomBytes(16);
  const publicKey = derivePublicKey(unlockSecret, kid, ARTIFACT_VERSION);

  // Missing kid
  const missingKidAttempt = spawnSync("pnpm", ["build:workspace:encrypted"], {
    stdio: "pipe",
    env: {
      ...process.env,
      WORKSPACE_PUBLIC_KEY_B64: publicKey.toString("base64"),
    },
  });
  if (missingKidAttempt.status === 0) {
    throw new Error("missing WORKSPACE_ARTIFACT_KID_B64 was accepted by encrypted build");
  }

  // All-zero kid
  const zeroKidAttempt = spawnSync("pnpm", ["build:workspace:encrypted"], {
    stdio: "pipe",
    env: {
      ...process.env,
      WORKSPACE_PUBLIC_KEY_B64: publicKey.toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: Buffer.alloc(16).toString("base64"),
    },
  });
  if (zeroKidAttempt.status === 0) {
    throw new Error("all-zero WORKSPACE_ARTIFACT_KID_B64 was accepted by encrypted build");
  }

  // All-zero public key
  const zeroPkAttempt = spawnSync("pnpm", ["build:workspace:encrypted"], {
    stdio: "pipe",
    env: {
      ...process.env,
      WORKSPACE_PUBLIC_KEY_B64: Buffer.alloc(32).toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
    },
  });
  if (zeroPkAttempt.status === 0) {
    throw new Error("all-zero WORKSPACE_PUBLIC_KEY_B64 was accepted by encrypted build");
  }

  // =========================================================================
  // 7. Establish expected payload plaintext digest from clean payload build
  // =========================================================================
  run(["build:workspace-payload"]);
  const expectedPackedPayload = await packDirectory(payloadDist);
  const expectedPayloadHash = digest(expectedPackedPayload);
  const expectedPayloadFiles = (await filesUnder(payloadDist)).map((p) => p.slice(payloadDist.length + 1)).sort();
  await rm(payloadDist, { recursive: true, force: true });

  // =========================================================================
  // 8. Normal encrypted build: only payload output sealed
  // =========================================================================
  run(["build:workspace:encrypted"], {
    ...process.env,
    WORKSPACE_PUBLIC_KEY_B64: publicKey.toString("base64"),
    WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
  });

  // 8a. Executable proof: Plaintext payload build directory must NOT exist after build
  try {
    await stat(payloadDist);
    throw new Error("plaintext payload build dist remains after encrypted build");
  } catch (e) {
    if (e?.code !== "ENOENT") throw e;
  }

  // 8b. Sealed artifact checks
  const rawArtifact = await readFile(artifactPath);

  // Scan artifact for plaintext leaks (no html/clear strings)
  for (const clear of ["index.html", "Workspace", "payload", "shell"]) {
    if (rawArtifact.includes(Buffer.from(clear))) {
      throw new Error(`artifact leaks plaintext metadata: ${clear}`);
    }
  }

  // Scan artifact for raw secret key material
  if (rawArtifact.includes(unlockSecret)) {
    throw new Error("artifact contains raw unlock secret");
  }

  // Validate envelope header structure
  if (rawArtifact.length <= ARTIFACT_HEADER_BYTES) {
    throw new Error("artifact smaller than minimum envelope header");
  }
  if (rawArtifact[0] !== ARTIFACT_VERSION) {
    throw new Error(`artifact has invalid version byte: ${rawArtifact[0]}`);
  }
  if (!rawArtifact.subarray(1, 17).equals(kid)) {
    throw new Error("artifact header kid mismatch");
  }

  // 8c. Decrypt with valid unlock secret & kid
  const { plaintext: decryptedPlaintext, files: unpackedMap } = await decryptArtifactFile(artifactPath, {
    WORKSPACE_UNLOCK_SECRET_B64: unlockSecret.toString("base64"),
    WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
  });
  if (digest(decryptedPlaintext) !== expectedPayloadHash) {
    throw new Error("decrypted artifact digest mismatch");
  }

  // 8d. Executable proof: Payload-only sealed archive (contains ONLY payload files, NO shell files)
  const unpackedNames = Array.from(unpackedMap.keys()).sort();
  if (JSON.stringify(unpackedNames) !== JSON.stringify(expectedPayloadFiles)) {
    throw new Error(`unpacked artifact file list does not match payload build: ${unpackedNames.join(", ")}`);
  }
  for (const name of unpackedNames) {
    if (name.includes("shell") || name.includes("wasm-loader") || name.includes("crypto-envelope-wasm")) {
      throw new Error(`unpacked artifact contains non-payload file: ${name}`);
    }
  }

  // =========================================================================
  // 9. Negative cryptographic tamper and error handling proofs
  // =========================================================================
  temp = await mkdtemp(join(tmpdir(), "web-boundary-test-"));

  // 9a. WORKSPACE_ARTIFACT_KEY_B64 rejected by decryptArtifactFile
  let forbiddenDecryptRejected = false;
  try {
    await decryptArtifactFile(artifactPath, {
      WORKSPACE_ARTIFACT_KEY_B64: randomBytes(32).toString("base64"),
      WORKSPACE_UNLOCK_SECRET_B64: unlockSecret.toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
    });
  } catch {
    forbiddenDecryptRejected = true;
  }
  if (!forbiddenDecryptRejected) {
    throw new Error("WORKSPACE_ARTIFACT_KEY_B64 was unexpectedly accepted by decryptArtifactFile");
  }

  // 9b. Tampered ciphertext fails closed
  const tamperedCt = Buffer.from(rawArtifact);
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

  // 9c. Tampered kid in header fails closed
  const tamperedKid = Buffer.from(rawArtifact);
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

  // 9d. Tampered version fails closed
  const tamperedVer = Buffer.from(rawArtifact);
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

  // 9e. Wrong unlock secret fails closed
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

  // 9f. Wrong kid in decrypt env fails closed
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
  if (!rejected) throw new Error("wrong kid in decrypt env was accepted");

  // 9g. All-zero kid in decrypt env fails closed
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

  // 9i. Preflight metadata: truncated artifact (< 65 bytes) fails closed in decrypt-artifact CLI
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

  // 9j. Missing kid fails closed on seal-artifact CLI
  const missingKidSeal = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "seal-artifact", "--",
    "--public-key-b64", publicKey.toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe" });
  if (missingKidSeal.status === 0) {
    throw new Error("missing kid was unexpectedly accepted by seal-artifact CLI");
  }

  // 9k. All-zero kid fails closed on seal-artifact CLI
  const zeroKidSeal = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "seal-artifact", "--",
    "--public-key-b64", publicKey.toString("base64"),
    "--kid-b64", Buffer.alloc(16).toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe" });
  if (zeroKidSeal.status === 0) {
    throw new Error("all-zero kid was unexpectedly accepted by seal-artifact CLI");
  }

  // 9l. Missing kid fails closed on decrypt-artifact CLI
  const missingKidDecrypt = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "decrypt-artifact", "--",
    "--unlock-secret-b64", unlockSecret.toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe" });
  if (missingKidDecrypt.status === 0) {
    throw new Error("missing kid was unexpectedly accepted by decrypt-artifact CLI");
  }

  // 9m. All-zero kid fails closed on decrypt-artifact CLI
  const zeroKidDecrypt = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "decrypt-artifact", "--",
    "--unlock-secret-b64", unlockSecret.toString("base64"),
    "--kid-b64", Buffer.alloc(16).toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe" });
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
  await rm(payloadDist, { recursive: true, force: true }).catch(() => {});
  await rm(shellDist, { recursive: true, force: true }).catch(() => {});
}
