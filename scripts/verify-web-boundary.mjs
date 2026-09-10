import { createHash, randomBytes } from "node:crypto";
import { spawnSync, spawn } from "node:child_process";
import { createServer } from "node:http";
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
let brokerProc;

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

  // 2b. Shell index.html carries fallback client-side meta tags (defense-in-depth; not claimed to enforce HTTP response headers)
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
  if (!cspContent.includes("frame-src blob:")) {
    throw new Error("shell CSP missing frame-src blob:");
  }
  // No external hosts or unconstrained origins
  if (/https?:\/\//i.test(cspContent) || cspContent.includes("*")) {
    throw new Error(`shell CSP contains non-own-origin or wildcard directive: ${cspContent}`);
  }

  // Verify no-store meta tag (client fallback)
  const cacheControlMatch = shellHtml.match(/<meta\s+http-equiv="Cache-Control"\s+content="([^"]+)"/i);
  if (!cacheControlMatch || !cacheControlMatch[1].includes("no-store")) {
    throw new Error("workspace-shell index.html missing Cache-Control: no-store meta tag");
  }

  // Verify nosniff meta tag (client fallback)
  const nosniffMatch = shellHtml.match(/<meta\s+http-equiv="X-Content-Type-Options"\s+content="nosniff"/i);
  if (!nosniffMatch) {
    throw new Error("workspace-shell index.html missing X-Content-Type-Options: nosniff meta tag");
  }

  // 2c. Production static-serving header artifact (_headers) enforces HTTP response headers
  const shellHeadersPath = join(shellDist, "_headers");
  const shellHeadersRaw = await readFile(shellHeadersPath, "utf8");
  const expectedCspHeader =
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src blob:; object-src 'none'; base-uri 'none'; form-action 'self'";

  // Parse standard static-host _headers format (Cloudflare Pages / Netlify convention)
  const headerRules = [];
  let currentHeaderRule = null;
  for (const rawLine of shellHeadersRaw.split("\n")) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (!rawLine.startsWith(" ") && !rawLine.startsWith("\t")) {
      currentHeaderRule = { path: trimmed, headers: {} };
      headerRules.push(currentHeaderRule);
    } else if (currentHeaderRule) {
      const colonIdx = trimmed.indexOf(":");
      if (colonIdx > 0) {
        const headerName = trimmed.slice(0, colonIdx).trim().toLowerCase();
        const headerValue = trimmed.slice(colonIdx + 1).trim();
        currentHeaderRule.headers[headerName] = headerValue;
      }
    }
  }

  const wildcardRule = headerRules.find((r) => r.path === "/*");
  if (!wildcardRule) {
    throw new Error("workspace-shell _headers missing universal wildcard rule (/*)");
  }
  if (wildcardRule.headers["cache-control"] !== "no-store") {
    throw new Error(`workspace-shell _headers Cache-Control mismatch: ${wildcardRule.headers["cache-control"]}`);
  }
  if (wildcardRule.headers["x-content-type-options"] !== "nosniff") {
    throw new Error(`workspace-shell _headers X-Content-Type-Options mismatch: ${wildcardRule.headers["x-content-type-options"]}`);
  }
  if (wildcardRule.headers["referrer-policy"] !== "no-referrer") {
    throw new Error(`workspace-shell _headers Referrer-Policy mismatch: ${wildcardRule.headers["referrer-policy"]}`);
  }
  if (wildcardRule.headers["content-security-policy"] !== expectedCspHeader) {
    throw new Error(`workspace-shell _headers Content-Security-Policy mismatch: ${wildcardRule.headers["content-security-policy"]}`);
  }
  const headerCsp = wildcardRule.headers["content-security-policy"];
  if (/https?:\/\//i.test(headerCsp) || headerCsp.includes("*")) {
    throw new Error(`shell _headers CSP contains non-own-origin or wildcard directive: ${headerCsp}`);
  }

  // 2d. Assert actual HTTP response headers via local static server consuming _headers
  const staticServer = createServer(async (req, res) => {
    const urlPath = (req.url || "/").split("?")[0];
    for (const rule of headerRules) {
      if (rule.path === "/*" || rule.path === urlPath) {
        for (const [k, v] of Object.entries(rule.headers)) {
          res.setHeader(k, v);
        }
      }
    }
    const relativeFile = urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, "");
    const targetFile = join(shellDist, relativeFile);
    try {
      const data = await readFile(targetFile);
      res.statusCode = 200;
      res.end(data);
    } catch {
      res.statusCode = 404;
      res.end("Not Found");
    }
  });

  await new Promise((res, rej) => {
    staticServer.listen(0, "127.0.0.1", () => res());
    staticServer.once("error", rej);
  });
  const serverAddress = staticServer.address();
  const serverPort = typeof serverAddress === "object" && serverAddress ? serverAddress.port : 0;
  try {
    const testPaths = ["/", "/index.html"];
    for (const file of shellBuiltFiles) {
      if (file !== shellHeadersPath) {
        testPaths.push("/" + file.slice(shellDist.length + 1));
      }
    }
    for (const reqPath of testPaths) {
      const resp = await fetch(`http://127.0.0.1:${serverPort}${reqPath}`);
      if (resp.status !== 200) {
        throw new Error(`static shell server returned status ${resp.status} for ${reqPath}`);
      }
      if (resp.headers.get("cache-control") !== "no-store") {
        throw new Error(`actual response for ${reqPath} missing Cache-Control: no-store`);
      }
      if (resp.headers.get("x-content-type-options") !== "nosniff") {
        throw new Error(`actual response for ${reqPath} missing X-Content-Type-Options: nosniff`);
      }
      if (resp.headers.get("referrer-policy") !== "no-referrer") {
        throw new Error(`actual response for ${reqPath} missing Referrer-Policy: no-referrer`);
      }
      if (resp.headers.get("content-security-policy") !== expectedCspHeader) {
        throw new Error(`actual response for ${reqPath} Content-Security-Policy mismatch`);
      }
    }
  } finally {
    await new Promise((res) => staticServer.close(res));
  }

  // 2e. Shell Vite config defines fail-closed server & preview headers
  const shellViteConfig = await readFile(resolve("web/workspace-shell/vite.config.ts"), "utf8");
  if (!shellViteConfig.includes('"Cache-Control": "no-store"') || !shellViteConfig.includes('"X-Content-Type-Options": "nosniff"')) {
    throw new Error("workspace-shell vite.config.ts missing fail-closed security headers");
  }
  if (!shellViteConfig.includes('"Referrer-Policy": "no-referrer"')) {
    throw new Error("workspace-shell vite.config.ts missing fail-closed Referrer-Policy header");
  }
  if (!shellViteConfig.includes("sourcemap: false")) {
    throw new Error("workspace-shell vite.config.ts must enforce sourcemap: false");
  }
  if (!shellViteConfig.includes("frame-src blob:")) {
    throw new Error("workspace-shell vite.config.ts missing frame-src blob: in Content-Security-Policy");
  }

  // 2f. Shell code & bundle contains no third-party network calls, analytics, or persistent storage
  const shellSourceFiles = [
    resolve("web/workspace-shell/src/index.tsx"),
    resolve("web/workspace-shell/src/wasm-loader.ts"),
    resolve("web/workspace-shell/src/unlock-runtime.ts"),
    shellHtmlPath,
    shellHeadersPath,
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

  // 2g. Shell iframe isolation and static CSP contract
  // Assert iframe has sandbox="allow-scripts" and strictly forbids allow-same-origin
  const iframeMatch = (await readFile(resolve("web/workspace-shell/src/index.tsx"), "utf8")).match(/<iframe[\s\S]*?\/>/);
  if (!iframeMatch) {
    throw new Error("workspace-shell src/index.tsx missing iframe element");
  }
  const iframeTag = iframeMatch[0];
  if (!iframeTag.includes('sandbox="allow-scripts"')) {
    throw new Error('workspace-shell src/index.tsx iframe missing sandbox="allow-scripts" attribute');
  }
  if (iframeTag.includes("allow-same-origin")) {
    throw new Error("workspace-shell src/index.tsx iframe improperly grants allow-same-origin");
  }
  for (const forbiddenSandbox of ["allow-top-navigation", "allow-modals", "allow-popups", "allow-same-origin"]) {
    if (iframeTag.includes(forbiddenSandbox)) {
      throw new Error(`workspace-shell iframe grants excessive sandbox privilege: ${forbiddenSandbox}`);
    }
  }
  const shellBundleJs = shellBuiltFiles.find((p) => /index-.*\.js$/.test(p));
  if (!shellBundleJs) {
    throw new Error("workspace-shell built bundle missing index-*.js");
  }
  const bundleContent = await readFile(shellBundleJs, "utf8");
  if (!bundleContent.includes("sandbox=allow-scripts") && !bundleContent.includes('sandbox="allow-scripts"')) {
    throw new Error("workspace-shell built bundle missing sandbox allow-scripts attribute");
  }
  if (bundleContent.includes("allow-same-origin")) {
    throw new Error("workspace-shell built bundle improperly contains allow-same-origin");
  }

  // =========================================================================
  // 3. Shell / payload circular-bootstrap prevention
  // =========================================================================
  // 3a. Shell source must NOT import workspace-payload
  const shellIndexSrc = await readFile(resolve("web/workspace-shell/src/index.tsx"), "utf8");
  const shellLoaderSrc = await readFile(resolve("web/workspace-shell/src/wasm-loader.ts"), "utf8");
  const shellUnlockSrc = await readFile(resolve("web/workspace-shell/src/unlock-runtime.ts"), "utf8");
  for (const [name, content] of [
    ["index.tsx", shellIndexSrc],
    ["wasm-loader.ts", shellLoaderSrc],
    ["unlock-runtime.ts", shellUnlockSrc],
  ]) {
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
  const payloadRawFiles = await filesUnder(payloadDist);
  for (const p of payloadRawFiles) {
    const rel = p.slice(payloadDist.length + 1);
    if (rel === "_headers" || rel.endsWith("/_headers") || rel.toLowerCase().includes("header")) {
      throw new Error(`payload dist contains forbidden header artifact: ${rel}`);
    }
  }
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
  for (const clear of [
    "index.html",
    "Workspace",
    "payload",
    "shell",
    "_headers",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
  ]) {
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

  // 8d. Executable proof: Payload-only sealed archive (contains ONLY payload files, NO shell or header files)
  const unpackedNames = Array.from(unpackedMap.keys()).sort();
  if (JSON.stringify(unpackedNames) !== JSON.stringify(expectedPayloadFiles)) {
    throw new Error(`unpacked artifact file list does not match payload build: ${unpackedNames.join(", ")}`);
  }
  if (unpackedNames.includes("_headers") || unpackedNames.some((n) => n.endsWith("/_headers") || n.toLowerCase().includes("header"))) {
    throw new Error("unpacked payload artifact contains forbidden header artifact");
  }
  for (const name of unpackedNames) {
    if (name.includes("shell") || name.includes("wasm-loader") || name.includes("crypto-envelope-wasm")) {
      throw new Error(`unpacked artifact contains non-payload file: ${name}`);
    }
  }
  if (decryptedPlaintext.includes(Buffer.from("_headers"))) {
    throw new Error("decrypted artifact contains _headers artifact reference");
  }
  if (decryptedPlaintext.includes(Buffer.from("X-Content-Type-Options"))) {
    throw new Error("decrypted artifact contains header configuration artifact reference");
  }
  if (decryptedPlaintext.includes(Buffer.from("Referrer-Policy"))) {
    throw new Error("decrypted artifact contains header configuration artifact reference");
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

  // =========================================================================
  // 10. Executable boundary shell proof with audited WASM and memory-only unlock runtime
  // =========================================================================
  console.log("verifying memory-only unlock runtime and audited wasm boundary...");

  const {
    WorkspaceUnlockRuntime,
    unpackPackageFromMemory,
    toBase64,
    fromBase64,
    loadWasm: loadShellWasm,
  } = await import("../web/workspace-shell/src/unlock-runtime.ts");

  // 10a. Audited WASM loads and binds
  await loadShellWasm();

  // 10b. Derive workspace keypair deterministically in WASM memory
  const wasmKey = new wasmModule.WasmWorkspaceKey(new Uint8Array(unlockSecret), ARTIFACT_VERSION, new Uint8Array(kid));
  try {
    const derivedPk = Buffer.from(wasmKey.public_key());
    if (!derivedPk.equals(publicKey)) {
      throw new Error("WasmWorkspaceKey derived public key mismatch");
    }
    if (!Buffer.from(wasmKey.kid()).equals(kid)) {
      throw new Error("WasmWorkspaceKey kid mismatch");
    }
    if (wasmKey.version() !== ARTIFACT_VERSION) {
      throw new Error("WasmWorkspaceKey version mismatch");
    }

    // Strict parameter validation in WASM key constructor
    let wasmRejected = false;
    try {
      new wasmModule.WasmWorkspaceKey(new Uint8Array(32), ARTIFACT_VERSION, new Uint8Array(kid));
    } catch {
      wasmRejected = true;
    }
    if (!wasmRejected) throw new Error("all-zero secret accepted by WasmWorkspaceKey");

    wasmRejected = false;
    try {
      new wasmModule.WasmWorkspaceKey(new Uint8Array(unlockSecret), ARTIFACT_VERSION, new Uint8Array(16));
    } catch {
      wasmRejected = true;
    }
    if (!wasmRejected) throw new Error("all-zero kid accepted by WasmWorkspaceKey");

    wasmRejected = false;
    try {
      new wasmModule.WasmWorkspaceKey(new Uint8Array(unlockSecret), 2, new Uint8Array(kid));
    } catch {
      wasmRejected = true;
    }
    if (!wasmRejected) throw new Error("unsupported version accepted by WasmWorkspaceKey");

    // Standalone convenience derive
    const convPk = Buffer.from(wasmModule.derive_workspace_public_key(new Uint8Array(unlockSecret), ARTIFACT_VERSION, new Uint8Array(kid)));
    if (!convPk.equals(publicKey)) {
      throw new Error("derive_workspace_public_key result mismatch");
    }

    // 10c. Decrypt inner artifact with WasmWorkspaceKey in memory
    const wasmDecryptedBytes = wasmKey.decrypt_artifact(new Uint8Array(rawArtifact));
    if (digest(Buffer.from(wasmDecryptedBytes)) !== expectedPayloadHash) {
      throw new Error("WasmWorkspaceKey decrypted payload digest mismatch");
    }

    // Standalone convenience decrypt
    const convDecrypted = wasmModule.decrypt_workspace_artifact(
      new Uint8Array(unlockSecret),
      ARTIFACT_VERSION,
      new Uint8Array(kid),
      new Uint8Array(rawArtifact),
    );
    if (digest(Buffer.from(convDecrypted)) !== expectedPayloadHash) {
      throw new Error("decrypt_workspace_artifact result mismatch");
    }

    // Negative crypto tamper checks directly in WASM:
    // Tampered ciphertext fails closed
    wasmRejected = false;
    try {
      wasmKey.decrypt_artifact(new Uint8Array(tamperedCt));
    } catch (e) {
      wasmRejected = true;
      if (String(e).includes(unlockSecret.toString("base64"))) {
        throw new Error("tampered ciphertext error leaked secret");
      }
    }
    if (!wasmRejected) throw new Error("WASM accepted tampered ciphertext");

    // Tampered kid fails closed
    wasmRejected = false;
    try {
      wasmKey.decrypt_artifact(new Uint8Array(tamperedKid));
    } catch {
      wasmRejected = true;
    }
    if (!wasmRejected) throw new Error("WASM accepted tampered kid");

    // Tampered version fails closed
    wasmRejected = false;
    try {
      wasmKey.decrypt_artifact(new Uint8Array(tamperedVer));
    } catch {
      wasmRejected = true;
    }
    if (!wasmRejected) throw new Error("WASM accepted tampered version");

    // Wrong secret key fails closed
    const wrongWasmKey = new wasmModule.WasmWorkspaceKey(new Uint8Array(wrongSecret), ARTIFACT_VERSION, new Uint8Array(kid));
    try {
      wasmRejected = false;
      try {
        wrongWasmKey.decrypt_artifact(new Uint8Array(rawArtifact));
      } catch (e) {
        wasmRejected = true;
        if (String(e).includes(wrongSecret.toString("base64"))) {
          throw new Error("wrong secret decrypt error leaked secret");
        }
      }
      if (!wasmRejected) throw new Error("WASM accepted wrong unlock secret");
    } finally {
      wrongWasmKey.free();
    }

    // 10d. Unpack package from memory without disk writes
    const inMemoryFiles = unpackPackageFromMemory(wasmDecryptedBytes);
    const inMemoryNames = Array.from(inMemoryFiles.keys()).sort();
    if (JSON.stringify(inMemoryNames) !== JSON.stringify(expectedPayloadFiles)) {
      throw new Error(`unpackPackageFromMemory file list mismatch: ${inMemoryNames.join(", ")}`);
    }
    if (!inMemoryFiles.has("index.html") || inMemoryFiles.get("index.html").length === 0) {
      throw new Error("unpackPackageFromMemory missing index.html");
    }

    // Negative package tests fail closed
    let packageRejected = false;
    try {
      unpackPackageFromMemory(new Uint8Array(3));
    } catch {
      packageRejected = true;
    }
    if (!packageRejected) throw new Error("truncated package accepted");

    packageRejected = false;
    try {
      unpackPackageFromMemory(new Uint8Array(100)); // zeroes = 0 file count
    } catch {
      packageRejected = true;
    }
    if (!packageRejected) throw new Error("zero-file package accepted");
  } finally {
    wasmKey.free();
  }

  // 10e. End-to-end WorkspaceUnlockRuntime lifecycle with mock transport server
  const runtime = new WorkspaceUnlockRuntime();
  if (runtime.unlocked) throw new Error("new runtime should not be unlocked");
  if (runtime.getActiveUrlCount() !== 0) throw new Error("new runtime should have 0 active urls");

  // Spawn test-session-host broker
  brokerProc = spawn("cargo", ["run", "--quiet", "-p", "crypto-envelope", "--example", "test-session-host"], {
    stdio: ["pipe", "pipe", "inherit"],
  });

  const brokerStdoutQueue = [];
  const brokerWaiters = [];
  let brokerLineBuf = "";
  brokerProc.stdout.on("data", (chunk) => {
    brokerLineBuf += chunk.toString();
    while (brokerLineBuf.includes("\n")) {
      const idx = brokerLineBuf.indexOf("\n");
      const line = brokerLineBuf.slice(0, idx).trim();
      brokerLineBuf = brokerLineBuf.slice(idx + 1);
      if (brokerWaiters.length > 0) {
        const resolveWait = brokerWaiters.shift();
        resolveWait(line);
      } else {
        brokerStdoutQueue.push(line);
      }
    }
  });

  function readBrokerLine() {
    if (brokerStdoutQueue.length > 0) {
      return Promise.resolve(brokerStdoutQueue.shift());
    }
    return new Promise((resolveWait) => brokerWaiters.push(resolveWait));
  }

  async function getBrokerOffer() {
    brokerProc.stdin.write("OFFER\n");
    const line = await readBrokerLine();
    const [offerKid, offerPk] = line.split(" ");
    return { offerKid, offerPk };
  }

  async function sealBrokerEnvelope(encKeyB64, inPath, outPath) {
    brokerProc.stdin.write(`SEAL ${encKeyB64} ${inPath} ${outPath}\n`);
    const line = await readBrokerLine();
    if (line !== "OK") throw new Error(`broker seal failed: ${line}`);
  }

  // Track what server receives to prove server retains ONLY public metadata
  const serverReceivedEnrollment = [];
  const tempEnvelopePath = join(temp, "test-runtime-envelope.bin");
  let activeOffer = null;

  const mockFetch = async (url, init = {}) => {
    const parsedUrl = new URL(url, "https://localhost:8081");
    if (parsedUrl.pathname === "/internal/auth/enroll") {
      const body = JSON.parse(init.body || "{}");
      serverReceivedEnrollment.push(body);
      // Server validates public key enrollment: canonical 32-byte public key, 16-byte kid, version 1
      if (
        body.version !== ARTIFACT_VERSION ||
        !body.kid ||
        !body.public_key
      ) {
        return { ok: false, status: 400 };
      }
      return { ok: true, status: 200, json: async () => ({ status: "enrolled" }) };
    }
    if (parsedUrl.pathname === "/internal/artifact/grant") {
      activeOffer = await getBrokerOffer();
      return {
        ok: true,
        status: 200,
        json: async () => ({
          grant_id: "test-grant-1",
          kid: activeOffer.offerKid,
          recipient_public_key: activeOffer.offerPk,
        }),
      };
    }
    if (parsedUrl.pathname === "/internal/artifact") {
      const body = JSON.parse(init.body || "{}");
      if (body.grant_id !== "test-grant-1" || !activeOffer || body.kid !== activeOffer.offerKid || !body.encapsulated_key) {
        return { ok: false, status: 400 };
      }
      // Seal rawArtifact using test-session-host broker
      await sealBrokerEnvelope(body.encapsulated_key, artifactPath, tempEnvelopePath);
      const envelopeData = await readFile(tempEnvelopePath);
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => envelopeData.buffer.slice(envelopeData.byteOffset, envelopeData.byteOffset + envelopeData.byteLength),
      };
    }
    return { ok: false, status: 404 };
  };

  const unlockResult = await runtime.unlock(
    unlockSecret.toString("base64"),
    kid.toString("base64"),
    {
      fetchFn: mockFetch,
    },
  );

  // 10f. Verify unlocked runtime state and payload mount
  if (!runtime.unlocked) throw new Error("runtime should be unlocked after successful unlock");
  if (runtime.getActiveUrlCount() === 0) throw new Error("runtime should have active blob URLs");
  if (!unlockResult.htmlUrl.startsWith("blob:")) throw new Error("mounted HTML URL must be a blob: URL");
  if (unlockResult.files.size !== expectedPayloadFiles.length) {
    throw new Error("mounted file count does not match payload build");
  }

  // Verify server received ONLY public metadata (never secret, private key, or content key)
  if (serverReceivedEnrollment.length < 1) {
    throw new Error("expected at least one enrollment request");
  }
  const enrollReq = serverReceivedEnrollment[0];
  if (enrollReq.version !== 1) throw new Error("enrollment version mismatch");
  if (enrollReq.kid !== kid.toString("base64")) throw new Error("enrollment kid mismatch");
  if (enrollReq.public_key !== publicKey.toString("base64")) throw new Error("enrollment public key mismatch");
  for (const forbidden of ["secret", "private_key", "content_key", "unlock_secret", "key"]) {
    if (forbidden in enrollReq) {
      throw new Error(`server enrollment received forbidden secret key field: ${forbidden}`);
    }
  }

  // 10g. Lock runtime: revokes blob URLs and scrubs RAM
  runtime.lock();
  if (runtime.unlocked) throw new Error("runtime should be locked after lock()");
  if (runtime.getActiveUrlCount() !== 0) throw new Error("runtime active URLs not revoked after lock()");

  // 10h. Negative runtime unlock tests fail closed with no secret leakage
  // Wrong unlock secret
  let unlockFailed = false;
  try {
    await runtime.unlock(
      wrongSecret.toString("base64"),
      kid.toString("base64"),
      {
        fetchFn: mockFetch,
      },
    );
  } catch (e) {
    unlockFailed = true;
    if (String(e).includes(wrongSecret.toString("base64"))) {
      throw new Error("unlock error leaked secret");
    }
  }
  if (!unlockFailed) throw new Error("runtime unlock accepted wrong secret");
  if (runtime.unlocked) throw new Error("runtime should remain locked on failure");
  if (runtime.getActiveUrlCount() !== 0) throw new Error("runtime should have 0 URLs on failure");

  // Wrong kid
  unlockFailed = false;
  try {
    await runtime.unlock(
      unlockSecret.toString("base64"),
      Buffer.from(wrongKid).toString("base64"),
      {
        fetchFn: mockFetch,
      },
    );
  } catch {
    unlockFailed = true;
  }
  if (!unlockFailed) throw new Error("runtime unlock accepted wrong kid");
  if (runtime.unlocked) throw new Error("runtime should remain locked on failure");

  // All-zero secret fails closed before network
  unlockFailed = false;
  try {
    await runtime.unlock(
      Buffer.alloc(32).toString("base64"),
      kid.toString("base64"),
      { fetchFn: mockFetch },
    );
  } catch {
    unlockFailed = true;
  }
  if (!unlockFailed) throw new Error("runtime accepted all-zero secret");

  // All-zero kid fails closed before network
  unlockFailed = false;
  try {
    await runtime.unlock(
      unlockSecret.toString("base64"),
      Buffer.alloc(16).toString("base64"),
      { fetchFn: mockFetch },
    );
  } catch {
    unlockFailed = true;
  }
  if (!unlockFailed) throw new Error("runtime accepted all-zero kid");

  // Server enrollment error fails closed
  unlockFailed = false;
  try {
    await runtime.unlock(
      unlockSecret.toString("base64"),
      kid.toString("base64"),
      {
        fetchFn: async (url) => {
          if (url.includes("enroll")) return { ok: false, status: 500 };
          return { ok: true };
        },
      },
    );
  } catch {
    unlockFailed = true;
  }
  if (!unlockFailed) throw new Error("runtime succeeded when server enrollment failed");
  if (runtime.unlocked) throw new Error("runtime should remain locked on server error");

  // Server enrollment 409 Conflict fails closed: stops before artifact-grant delivery, exposes no secret
  let grantAttemptedOn409 = false;
  let deliverAttemptedOn409 = false;
  let enrollPayload409 = null;
  unlockFailed = false;
  try {
    await runtime.unlock(
      unlockSecret.toString("base64"),
      kid.toString("base64"),
      {
        fetchFn: async (url, init = {}) => {
          const parsed = new URL(url, "https://localhost:8081");
          if (parsed.pathname.includes("enroll")) {
            enrollPayload409 = init.body ? JSON.parse(init.body) : null;
            return { ok: false, status: 409 };
          }
          if (parsed.pathname.includes("grant")) {
            grantAttemptedOn409 = true;
            return { ok: false, status: 500 };
          }
          if (parsed.pathname.includes("artifact")) {
            deliverAttemptedOn409 = true;
            return { ok: false, status: 500 };
          }
          return { ok: false, status: 404 };
        },
      },
    );
  } catch (e) {
    unlockFailed = true;
    if (String(e).includes(unlockSecret.toString("base64"))) {
      throw new Error("409 enrollment conflict error leaked unlock secret in error message");
    }
  }
  if (!unlockFailed) throw new Error("runtime succeeded when server enrollment returned 409 Conflict");
  if (grantAttemptedOn409) throw new Error("runtime attempted artifact grant after 409 enrollment conflict");
  if (deliverAttemptedOn409) throw new Error("runtime attempted artifact delivery after 409 enrollment conflict");
  if (runtime.unlocked) throw new Error("runtime should remain locked on 409 enrollment conflict");
  if (runtime.getActiveUrlCount() !== 0) throw new Error("runtime active URLs must remain 0 on 409 failure");
  if (enrollPayload409) {
    for (const forbidden of ["secret", "private_key", "content_key", "unlock_secret", "key"]) {
      if (forbidden in enrollPayload409) {
        throw new Error(`409 enrollment payload leaked forbidden secret field: ${forbidden}`);
      }
    }
  }

  // Shutdown broker
  if (brokerProc) {
    try {
      brokerProc.stdin.write("QUIT\n");
      brokerProc.kill();
      brokerProc = null;
    } catch {}
  }

  console.log("web boundary verification passed");
} finally {
  if (brokerProc) {
    try {
      brokerProc.stdin.write("QUIT\n");
      brokerProc.kill();
    } catch {}
  }
  if (unlockSecret) unlockSecret.fill(0);
  delete process.env.WORKSPACE_PUBLIC_KEY_B64;
  delete process.env.WORKSPACE_ARTIFACT_KID_B64;
  delete process.env.WORKSPACE_UNLOCK_SECRET_B64;
  delete process.env.WORKSPACE_ARTIFACT_KEY_B64;
  if (temp) await rm(temp, { recursive: true, force: true }).catch(() => {});
  await rm(payloadDist, { recursive: true, force: true }).catch(() => {});
  await rm(shellDist, { recursive: true, force: true }).catch(() => {});
}
