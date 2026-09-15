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
  sealPackage,
  unpackPackage,
  artifactPublicKeyFromEnv,
  artifactKidFromEnv,
  unlockSecretFromEnv,
} from "./workspace-artifact.mjs";

function run(args, env = process.env) {
  const result = spawnSync("pnpm", args, { stdio: "inherit", env });
  if (result.status !== 0) throw new Error(`command failed: pnpm ${args.join(" ")}`);
}

/**
 * A negative CLI test only proves the boundary if the CLI actually ran. A
 * missing toolchain (`status === null` / `result.error`) must fail the gate, not
 * be mistaken for a correct rejection.
 */
function assertCliRejected(result, label) {
  if (result.error) {
    throw new Error(`${label}: CLI could not be executed (${result.error.message})`);
  }
  if (result.status === null) {
    throw new Error(`${label}: CLI did not terminate`);
  }
  if (result.status === 0) {
    throw new Error(label);
  }
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
  "localstorage",
  "sessionstorage",
  "indexeddb",
  "caches",
  "document.cookie",
  "window.name",
  "navigator.storage",
  "getdirectory",
  "broadcastchannel",
  "sharedworker",
  "serviceworker",
  "opendatabase",
];

// Domain/package-specific so common English words ("segment", "sentry") in
// legitimate libraries do not false-positive. Covers the SDKs that would ship an
// analytics/telemetry endpoint or package import.
const trackerTerms = [
  "google-analytics.com",
  "googletagmanager.com",
  "mixpanel.com",
  "segment.com",
  "segment.io",
  "cdn.segment.",
  "sentry.io",
  "sentry-cdn.com",
  "@sentry/",
  "posthog.com",
  "posthog-js",
  "amplitude.com",
  "@amplitude/",
  "fullstory.com",
  "fullstory.com/s/fs.js",
  "logrocket.com",
  "logrocket.io",
  "@logrocket/",
  "hotjar.com",
  "static.hotjar.com",
  "clarity.ms",
  "@microsoft/clarity",
  "datadoghq-browser-agent",
  "datadoghq.com",
  "@datadog/browser",
  "newrelic.com",
  "js-agent.newrelic.com",
  "@newrelic/browser-agent",
  "bugsnag.com",
  "bugsnag-js",
  "@bugsnag/",
  "rollbar.com",
  "rollbar.js",
  "plausible.io",
  "matomo.org",
  "matomo.cloud",
  "heap.io",
  "heap-analytics",
  "smartlook.com",
  "quantummetric.com",
  "contentsquare.net",
];

/**
 * Own-origin URL scanner shared by the shell and payload boundaries. (The public
 * site is intentionally scanned only for trackers and source maps: it is a
 * separate non-private build and may legitimately link out.)
 */
function assertNoExternalUrls(text, label) {
  for (const match of text.matchAll(/(?:https?|wss?):\/\/[^"'`\s)<]+/gi)) {
    const raw = match[0];
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      throw new Error(`${label} contains malformed URL: ${raw}`);
    }
    const host = parsed.hostname.toLowerCase();
    if (host === "localhost" || host === "w3.org" || host.endsWith(".w3.org")) continue;
    throw new Error(`${label} contains non-own-origin URL: ${raw}`);
  }
  for (const match of text.matchAll(
    /(?<!:)\/\/(\[[0-9a-fA-F:]+\]|[a-z0-9-]+(?:\.[a-z0-9-]+)+)/g,
  )) {
    let parsed;
    try {
      parsed = new URL(`https://${match[1]}`);
    } catch {
      continue;
    }
    const host = parsed.hostname.toLowerCase();
    if (host === "localhost" || host === "w3.org" || host.endsWith(".w3.org")) continue;
    throw new Error(`${label} contains protocol-relative external URL: ${match[0]}`);
  }
}

function assertNoTrackers(text, label) {
  const lower = collapseStringConcatenation(text).toLowerCase();
  for (const tracker of trackerTerms) {
    if (lower.includes(tracker)) throw new Error(`${label} references external tracker: ${tracker}`);
  }
}

function assertNoForbiddenStorage(text, label) {
  const lower = collapseStringConcatenation(text).toLowerCase();
  for (const term of forbiddenStorageTerms) {
    if (lower.includes(term)) throw new Error(`${label} references forbidden storage API: ${term}`);
  }
  // Defeat trivial bracket-notation concatenation (`window["local"+"Storage"]`)
  // including the object qualifier, so `document["cookie"]` /
  // `window["name"]` match the dotted deny-list too. The regex is deliberately
  // narrow (a run of string literals inside one bracket access) so ordinary
  // minified identifiers do not false-positive.
  for (const match of lower.matchAll(
    /([a-z_$][\w$]*)\s*\[\s*((?:(?:["'`][^"'`]*["'`])\s*(?:\+\s*)?)+)\s*\]/g,
  )) {
    const object = match[1];
    const joined = match[2].replace(/["'`+\s]/g, "");
    const qualified = `${object}.${joined}`;
    for (const term of forbiddenStorageTerms) {
      if (joined.includes(term) || qualified.includes(term)) {
        throw new Error(`${label} computes a forbidden storage API: ${term}`);
      }
    }
  }
}

/**
 * Runtime document/location writes are a way to leak trading semantics into the
 * URL, title, favicon or history even when the shipped HTML metadata is neutral.
 * Only *writes* are matched: reading `location.origin` is legitimate.
 */
const forbiddenMetadataWritePatterns = [
  /document\s*\.\s*title\s*=/i,
  /document\s*\[\s*["'`]title["'`]\s*\]\s*=/i,
  /history\s*\.\s*(?:pushState|replaceState)\s*\(/i,
  /history\s*\[\s*["'`](?:pushState|replaceState)["'`]\s*\]\s*\(/i,
  /location\s*\.\s*(?:hash|search|pathname|href)\s*=/i,
  /(?:window\s*\.\s*)?location\s*\[\s*["'`](?:href|hash|search|pathname)["'`]\s*\]\s*=/i,
  /window\s*\.\s*location\s*=/i,
  /location\s*\.\s*(?:assign|replace)\s*\(/i,
  /(?:window\s*\.\s*)?location\s*\[\s*["'`](?:assign|replace)["'`]\s*\]\s*\(/i,
  /navigation\s*\.\s*navigate\s*\(/i,
  /navigation\s*\[\s*["'`]navigate["'`]\s*\]\s*\(/i,
  /document\s*\.\s*cookie\s*=/i,
  /document\s*\[\s*["'`]cookie["'`]\s*\]\s*=/i,
  // Title-element mutation (`document.querySelector("title").textContent = …`,
  // `document.title…` via a variable is not statically observable, but the direct
  // element write is).
  /(?:querySelector(?:All)?|getElementsByTagName)\s*\(\s*["'`][^"'`]*title[^"'`]*["'`]\s*\)[\s\S]{0,80}?\.\s*(?:textContent|innerHTML|innerText)\s*=/i,
];

function assertNoRuntimeMetadataWrites(text, label) {
  const normalized = collapseStringConcatenation(text);
  for (const pattern of forbiddenMetadataWritePatterns) {
    if (pattern.test(normalized)) {
      throw new Error(
        `${label} writes runtime document/location metadata (${pattern.source}) — private semantics must not reach the URL/title/history`,
      );
    }
  }
}

/**
 * Provider endpoints and credential names must never reach the browser bundle
 * (W13 / architecture lock L2): the web app asks the neutral first-party
 * contract for a routing source, and OKX is called only by the backend. A bare
 * provider *label* ("okx" as a capability key or UI label) is allowed; a
 * hostname, API path or credential name is not.
 */
const providerEndpointTerms = [
  "okx.com",
  "okx.cab",
  "oklink.com",
  "api.okx",
  "ws.okx",
  "okx_api_key",
  "okx_api_secret",
  "okx_secret",
  "okx_passphrase",
  "okx-api-key",
  "okx_secret_key",
  // camelCase / kebab credential spellings and OKX's real request headers.
  "okxapikey",
  "okxapisecret",
  "okxsecret",
  "okxpassphrase",
  "okx-secret",
  "ok-access-",
  "okaccesskey",
  "okaccesssign",
  "okaccesspassphrase",
  "dexscreener.com",
  "api.dexscreener",
  "tradingview.com",
  "gmgn.ai",
  "api.gmgn",
  "jup.ag",
  "quote-api.jup",
  "api.binance",
  "api.raydium",
];

/**
 * Collapse adjacent string-literal concatenation (`"local" + "Storage"`,
 * `document["ti" + "tle"]`, `"okx" + ".com"`) into the literal it resolves to,
 * so the deny-list scans cannot be evaded by splitting a forbidden token across
 * two literals. Bounded to a few passes; only string-literal `+` literal pairs
 * are joined, so ordinary code is unaffected.
 */
function collapseStringConcatenation(text) {
  // The `{0,256}` bound keeps the scan linear-ish on minified bundles: a
  // forbidden token split across literals is only a few characters per side.
  const pattern =
    /(["'`])((?:\\.|(?!\1)[\s\S]){0,256})\1\s*\+\s*(["'`])((?:\\.|(?!\3)[\s\S]){0,256})\3/g;
  let current = text;
  for (let pass = 0; pass < 8; pass += 1) {
    const next = current.replace(pattern, (_match, quote, left, _q, right) =>
      `${quote}${left}${right}${quote}`,
    );
    if (next === current) break;
    current = next;
  }
  return current;
}

function assertNoProviderEndpoints(text, label) {
  const lower = collapseStringConcatenation(text).toLowerCase();
  for (const term of providerEndpointTerms) {
    if (lower.includes(term)) {
      throw new Error(`${label} references a provider endpoint/credential: ${term}`);
    }
  }
}

/**
 * Positive/negative controls for the text scanners. A gate that silently stops
 * matching is worse than no gate, so prove each deny-list fires on the split-
 * literal/computed-key evasions it claims to cover, and that benign code is not
 * rejected. Runs on every gate invocation.
 */
function assertScannerControls() {
  const mustReject = [
    ["storage dotted", () => assertNoForbiddenStorage('localStorage.setItem("a","b")', "control")],
    [
      "storage split-literal computed key",
      () => assertNoForbiddenStorage('const k="local"+"Storage"; window[k].setItem("a","b")', "control"),
    ],
    [
      "indexeddb split-literal alias",
      () => assertNoForbiddenStorage('const key="inde"+"xedDB"; globalThis[key]', "control"),
    ],
    [
      "metadata split-literal title",
      () => assertNoRuntimeMetadataWrites('document["ti"+"tle"]="swap"', "control"),
    ],
    [
      "metadata split-literal history",
      () =>
        assertNoRuntimeMetadataWrites('history["push"+"State"]({}, "", "/swap?amount=5")', "control"),
    ],
    [
      "metadata split-literal hash",
      () => assertNoRuntimeMetadataWrites('window.location["ha"+"sh"]="#/trade"', "control"),
    ],
    ["provider split-literal host", () => assertNoProviderEndpoints('fetch("okx"+".com")', "control")],
    ["provider ok-access header", () => assertNoProviderEndpoints('"OK-ACCESS-KEY"', "control")],
    ["provider camelCase credential", () => assertNoProviderEndpoints("const okxApiKey = 1;", "control")],
  ];
  for (const [name, run] of mustReject) {
    let rejected = false;
    try {
      run();
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error(`boundary scanner self-test failed: ${name} was not rejected`);
  }
  // Benign code must not be rejected (guards against an over-broad collapse or
  // deny-list term).
  assertNoForbiddenStorage('const label = "local" + " router"; console.log(label)', "control");
  assertNoProviderEndpoints('const capability = "okx";', "control");
  assertNoRuntimeMetadataWrites('const href = location.origin + "/v1/blob";', "control");
}
assertScannerControls();

/**
 * Invariant: no trading semantics in the document title or social metadata. The
 * private payload legitimately contains trading code, but its *document metadata*
 * must stay neutral (it can be read from a tab, history or a link preview).
 */
const TRADING_METADATA_TERMS = [
  "swap",
  "trade",
  "trading",
  "dex",
  "wallet",
  "jupiter",
  "raydium",
  "uniswap",
  "solana",
  "binance",
  "okx",
  "gmgn",
  "fomo",
  "privy",
  "limit order",
  "execution",
  "order book",
  "portfolio",
];

function assertNeutralDocumentMetadata(html, label) {
  // Every <title> (a second one is itself suspicious) must be neutral.
  const titles = [...html.matchAll(/<title[^>]*>([\s\S]*?)<\/title>/gi)];
  if (titles.length === 0) {
    throw new Error(`${label} has no <title> (document metadata was not verifiable)`);
  }
  for (const match of titles) {
    const title = match[1].trim().toLowerCase();
    for (const term of TRADING_METADATA_TERMS) {
      if (title.includes(term)) throw new Error(`${label} title leaks a trading semantic: ${term}`);
    }
  }
  if (/<meta[^>]+property=["']og:/i.test(html)) {
    throw new Error(`${label} emits OpenGraph metadata (private semantics in link previews)`);
  }
  if (/<meta[^>]+name=["']twitter:/i.test(html)) {
    throw new Error(`${label} emits Twitter card metadata`);
  }
  // Any meta `content` value (description, keywords, application-name, …) can be
  // surfaced in a link preview / search result, so all of them must stay neutral,
  // not only og:/twitter:.
  for (const match of html.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = match[0];
    const contentMatch = tag.match(/content\s*=\s*["']([^"']*)["']/i);
    if (!contentMatch) continue;
    const content = contentMatch[1].toLowerCase();
    for (const term of TRADING_METADATA_TERMS) {
      if (content.includes(term)) {
        throw new Error(`${label} meta content leaks a trading semantic: ${term}`);
      }
    }
  }
}

let unlockSecret;
let temp;
let brokerProc;

try {
  // =========================================================================
  // 0. Private payload focused suite (state, transport allowlist, protocol,
  //    component fail-closed behaviour). Runs inside the CI web-boundary job.
  // =========================================================================
  run(["test:web"]);

  // =========================================================================
  // 1. Verify public build does not leak private terms or source maps
  // =========================================================================
  run(["build:public"]);
  for (const path of await filesUnder(publicOut)) {
    if (path.endsWith(".map")) throw new Error("public source map detected");
    if (/\.(?:m?js|html|css|json)$/i.test(path)) {
      const text = await readFile(path, "utf8");
      const lower = text.toLowerCase();
      for (const term of [
        "@evergreen/workspace-payload",
        "web/workspace-payload",
        "@evergreen/workspace",
        "web/workspace",
        ...forbiddenTradingTerms,
      ]) {
        if (lower.includes(term.toLowerCase())) {
          throw new Error(`public bundle privacy term detected: ${term}`);
        }
      }
      assertNoTrackers(text, `public bundle ${path}`);
      if (text.includes("sourceMappingURL")) {
        throw new Error(`public bundle ${path} references a source map`);
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

  // Verify CSP meta tag. `frame-ancestors` cannot be enforced from <meta>
  // (browsers ignore it there), so the meta policy is compared EXACTLY and the
  // framing control is asserted on the real HTTP response CSP below.
  const expectedShellMetaCsp =
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' blob:; style-src 'self' blob:; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-src blob:; worker-src 'self' blob: data:; object-src 'none'; base-uri 'none'; form-action 'self'";
  const cspMatch = shellHtml.match(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i);
  if (!cspMatch) {
    throw new Error("workspace-shell index.html missing Content-Security-Policy meta tag");
  }
  const cspContent = cspMatch[1];
  if (cspContent !== expectedShellMetaCsp) {
    throw new Error(
      `shell meta CSP mismatch (exact policy required; no 'unsafe-inline'/'unsafe-eval' additions):\n  expected: ${expectedShellMetaCsp}\n  actual:   ${cspContent}`,
    );
  }
  // No external hosts or unconstrained origins
  if (/https?:\/\//i.test(cspContent) || cspContent.includes("*")) {
    throw new Error(`shell CSP contains non-own-origin or wildcard directive: ${cspContent}`);
  }
  // No trading semantics in the shell document metadata.
  assertNeutralDocumentMetadata(shellHtml, "workspace-shell index.html");

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
  const expectedCspHeader = `${expectedShellMetaCsp}; frame-ancestors 'none'`;

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
  if (wildcardRule.headers["x-frame-options"] !== "DENY") {
    throw new Error(`workspace-shell _headers X-Frame-Options mismatch: ${wildcardRule.headers["x-frame-options"]}`);
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
      if (resp.headers.get("x-frame-options") !== "DENY") {
        throw new Error(`actual response for ${reqPath} missing X-Frame-Options: DENY (clickjacking of the unlock secret)`);
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
  if (!/(^|[{\s,])sourcemap\s*:\s*false\s*(,|\})/m.test(shellViteConfig)) {
    throw new Error("workspace-shell vite.config.ts must enforce sourcemap: false exactly");
  }
  // The build script must not re-enable source maps (e.g. `vite build --sourcemap`)
  // behind the config property; inline maps emit no `.map` file and would pass a
  // file-extension-only scan.
  const shellPkgRaw = await readFile(resolve("web/workspace-shell/package.json"), "utf8");
  let shellPkg = null;
  try {
    shellPkg = JSON.parse(shellPkgRaw);
  } catch {
    throw new Error("workspace-shell package.json is not valid JSON");
  }
  const shellBuildScript = String(shellPkg?.scripts?.build ?? "");
  if (/--sourcemap\b/i.test(shellBuildScript)) {
    throw new Error("workspace-shell build script enables source maps");
  }
  if (!shellViteConfig.includes('"X-Frame-Options": "DENY"')) {
    throw new Error("workspace-shell vite.config.ts missing X-Frame-Options: DENY");
  }
  if (!shellViteConfig.includes(expectedCspHeader)) {
    throw new Error(
      "workspace-shell vite.config.ts must pin the exact fail-closed CSP (including frame-ancestors 'none')",
    );
  }

  // 2f. Shell code & bundle contains no third-party network calls, analytics, or persistent storage
  const shellSourceFiles = [
    resolve("web/workspace-shell/src/index.tsx"),
    resolve("web/workspace-shell/src/passkey-auth.ts"),
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
    assertNoForbiddenStorage(text, `shell file ${path}`);
    // No runtime URL/title/history metadata writes
    assertNoRuntimeMetadataWrites(text, `shell file ${path}`);
    // No private trading semantics
    for (const term of forbiddenTradingTerms) {
      if (text.toLowerCase().includes(term.toLowerCase())) {
        throw new Error(`shell file ${path} encodes private trading semantic: ${term}`);
      }
    }
    // No external network endpoints (http/https/ws/wss + protocol-relative) or analytics
    assertNoExternalUrls(text, `shell file ${path}`);
    assertNoTrackers(text, `shell file ${path}`);
    // No provider endpoint/credential literals either (a bare `okx_api_key`
    // string has no URL for the external-origin scanner to catch).
    assertNoProviderEndpoints(text, `shell file ${path}`);
    // No source maps — including inline (`sourceMappingURL=data:...`) maps that
    // emit no `.map` file and would otherwise ship the full shell source.
    if (text.includes("sourceMappingURL")) {
      throw new Error(`shell file ${path} references a source map`);
    }
  }

  // 2g. Shell iframe sandbox configuration and static CSP contract
  //
  // The decrypted payload is instantiated from blob: URLs created by the shell
  // document. A sandboxed *opaque* origin cannot load those blob: subresources
  // (Chromium refuses them as "local resource"), so the frame must be
  // same-origin. All navigation/popup/modal/form/download privileges stay denied.
  //
  // CAVEAT (BR-6): with `allow-same-origin` the sandbox is NOT a containment
  // boundary — a same-origin document can remove its own sandbox. This assertion
  // pins the intended configuration and the denied privilege set; it must not be
  // read as a security control. The payload is treated as trusted code, and the
  // shell authorizes lock requests by `event.source === frame.contentWindow`.
  // Real containment requires serving the payload from a distinct origin.
  const iframeMatch = (await readFile(resolve("web/workspace-shell/src/index.tsx"), "utf8")).match(/<iframe[\s\S]*?\/>/);
  if (!iframeMatch) {
    throw new Error("workspace-shell src/index.tsx missing iframe element");
  }
  const iframeTag = iframeMatch[0];
  if (!iframeTag.includes('sandbox="allow-scripts allow-same-origin"')) {
    throw new Error(
      'workspace-shell src/index.tsx iframe must use sandbox="allow-scripts allow-same-origin" so the in-memory blob: payload can execute',
    );
  }
  for (const forbiddenSandbox of [
    "allow-top-navigation",
    "allow-top-navigation-by-user-activation",
    "allow-modals",
    "allow-popups",
    "allow-forms",
    "allow-downloads",
    "allow-pointer-lock",
    "allow-presentation",
  ]) {
    if (iframeTag.includes(forbiddenSandbox)) {
      throw new Error(`workspace-shell iframe grants excessive sandbox privilege: ${forbiddenSandbox}`);
    }
  }
  const shellBundleJs = shellBuiltFiles.find((p) => /index-.*\.js$/.test(p));
  if (!shellBundleJs) {
    throw new Error("workspace-shell built bundle missing index-*.js");
  }
  const bundleContent = await readFile(shellBundleJs, "utf8");
  if (!bundleContent.includes("allow-scripts") || !bundleContent.includes("allow-same-origin")) {
    throw new Error(
      "workspace-shell built bundle missing sandbox allow-scripts allow-same-origin",
    );
  }

  // =========================================================================
  // 3. Shell / payload circular-bootstrap prevention
  // =========================================================================
  // 3a. No shell source file (any depth) may reference the private payload
  for (const path of await filesUnder(resolve("web/workspace-shell/src"))) {
    if (!/\.(?:ts|tsx|js|jsx|mjs|cjs|css|html)$/i.test(path)) continue;
    const content = await readFile(path, "utf8");
    if (content.includes("workspace-payload") || content.includes("@evergreen/workspace-payload")) {
      throw new Error(`circular bootstrap: shell source ${path} imports private payload`);
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
  // 3c. No payload source file (any depth) may reference the cleartext shell
  for (const path of await filesUnder(resolve("web/workspace-payload/src"))) {
    if (!/\.(?:ts|tsx|js|jsx|mjs|cjs|css|html)$/i.test(path)) continue;
    const content = await readFile(path, "utf8");
    if (content.includes("workspace-shell") || content.includes("@evergreen/workspace-shell")) {
      throw new Error(`circular bootstrap: payload source ${path} imports the workspace shell`);
    }
  }
  // 3d. Provider endpoints/credentials must never appear in *source* either, not
  // only in the emitted bundle: an unimported source file is still a repository
  // risk, and the built-bundle scan (7a) only covers what is actually emitted.
  // Test files are exempt because they legitimately hold forbidden literals as
  // negative fixtures (e.g. `assertNeutralUrl("https://gmgn.ai/x")`); tests are
  // never emitted, so the dist scan remains the shipped-code guarantee.
  const isTestSource = (path) => /\.(?:test|spec)\.(?:ts|tsx|js|jsx|mjs|cjs)$/i.test(path);
  const isTextSource = (path) => /\.(?:ts|tsx|js|jsx|mjs|cjs|css|html)$/i.test(path);
  for (const path of await filesUnder(resolve("web/workspace-payload/src"))) {
    if (!isTextSource(path) || isTestSource(path)) continue;
    assertNoProviderEndpoints(await readFile(path, "utf8"), `payload source ${path}`);
  }
  for (const path of await filesUnder(resolve("web/workspace-shell/src"))) {
    if (!isTextSource(path) || isTestSource(path)) continue;
    assertNoProviderEndpoints(await readFile(path, "utf8"), `shell source ${path}`);
  }
  // 3e. The shell's artifact-enrollment network contract is first-party only.
  // `transport/paths.ts` allowlists the *payload's* neutral `/v1/*` paths; the
  // cleartext shell additionally talks to the artifact endpoints below. Assert
  // that exact set so an un-neutral new path cannot be added silently (L2).
  const SHELL_PRIVATE_PATHS = [
    "/internal/artifact",
    "/internal/artifact/grant",
    "/internal/auth/challenge",
    "/internal/auth/enroll",
    "/internal/auth/enrollment-status",
    "/internal/auth/register/challenge",
    "/internal/auth/register/verify",
    "/internal/auth/session",
    "/internal/auth/verify",
    "/internal/workspace/descriptor",
  ];
  const shellPrivatePaths = new Set();
  for (const path of await filesUnder(resolve("web/workspace-shell/src"))) {
    if (!isTextSource(path) || isTestSource(path)) continue;
    const text = await readFile(path, "utf8");
    for (const match of text.matchAll(/["'`](\/internal\/[A-Za-z0-9._/-]+)["'`]/g)) {
      shellPrivatePaths.add(match[1]);
    }
  }
  const shellPrivateSorted = [...shellPrivatePaths].sort();
  const expectedPrivateSorted = [...SHELL_PRIVATE_PATHS].sort();
  if (JSON.stringify(shellPrivateSorted) !== JSON.stringify(expectedPrivateSorted)) {
    throw new Error(
      `shell first-party path drift:\n  expected: ${expectedPrivateSorted.join(", ")}\n` +
        `  actual:   ${shellPrivateSorted.join(", ")}`,
    );
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
  // Integrity pin: the "audited" wasm must be the exact artifact this gate was
  // written against. A substituted same-size binary that derives the same public
  // key would otherwise pass the Rust-CLI comparison below while behaving
  // differently. Regenerating the wasm is a reviewed change: update this digest
  // in the same commit.
  const EXPECTED_WASM_SHA256 =
    "60d2b137f2b8449c4ecb19a561726a047b1020344cf5dcac22871bd6a11744a8";
  const wasmSha256 = digest(wasmBytes);
  if (wasmSha256 !== EXPECTED_WASM_SHA256) {
    throw new Error(
      `vendored audited wasm digest mismatch:\n  expected: ${EXPECTED_WASM_SHA256}\n  actual:   ${wasmSha256}\n` +
        "If the wasm was intentionally regenerated, update the pin after review.",
    );
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
  assertCliRejected(
    forbiddenBuildAttempt,
    "WORKSPACE_ARTIFACT_KEY_B64 was unexpectedly accepted by encrypted build",
  );

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
  assertCliRejected(
    missingKidAttempt,
    "missing WORKSPACE_ARTIFACT_KID_B64 was accepted by encrypted build",
  );

  // All-zero kid
  const zeroKidAttempt = spawnSync("pnpm", ["build:workspace:encrypted"], {
    stdio: "pipe",
    env: {
      ...process.env,
      WORKSPACE_PUBLIC_KEY_B64: publicKey.toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: Buffer.alloc(16).toString("base64"),
    },
  });
  assertCliRejected(
    zeroKidAttempt,
    "all-zero WORKSPACE_ARTIFACT_KID_B64 was accepted by encrypted build",
  );

  // All-zero public key
  const zeroPkAttempt = spawnSync("pnpm", ["build:workspace:encrypted"], {
    stdio: "pipe",
    env: {
      ...process.env,
      WORKSPACE_PUBLIC_KEY_B64: Buffer.alloc(32).toString("base64"),
      WORKSPACE_ARTIFACT_KID_B64: kid.toString("base64"),
    },
  });
  assertCliRejected(
    zeroPkAttempt,
    "all-zero WORKSPACE_PUBLIC_KEY_B64 was accepted by encrypted build",
  );

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

  // 7a. Private payload privacy boundary: no persistent browser storage, no
  // direct external origins (own neutral paths only), no analytics/session
  // recording, and no source maps. Private trading semantics ARE expected here
  // (this is the encrypted private app), unlike the cleartext shell.
  for (const p of payloadRawFiles) {
    if (p.endsWith(".map")) {
      throw new Error(`payload emitted forbidden source map: ${p}`);
    }
    // Persistent-storage and provider-endpoint scans run over EVERY payload file
    // (including binaries and extensionless assets) so a forbidden API or a
    // provider hostname/credential hidden in a `.wasm`, image or font cannot slip
    // past a text-only allowlist.
    const latin1 = (await readFile(p)).toString("latin1");
    assertNoForbiddenStorage(latin1, `payload file ${p}`);
    assertNoProviderEndpoints(latin1, `payload file ${p}`);
    if (!/\.(?:m?js|cjs|html|css|json|svg|txt|webmanifest)$/i.test(p)) continue;
    const text = await readFile(p, "utf8");
    // Any absolute network scheme (http/https/ws/wss) that is not loopback or a
    // pure XML namespace is an external dependency and must not be shipped.
    // Host is parsed (not string-prefixed) so `localhost.evil.example`,
    // `localhost@evil.example` and `?u=w3.org/` cannot smuggle an external host.
    assertNoExternalUrls(text, `payload file ${p}`);
    assertNoTrackers(text, `payload file ${p}`);
    assertNoRuntimeMetadataWrites(text, `payload file ${p}`);
    if (text.includes("sourceMappingURL")) {
      throw new Error(`payload file ${p} references a source map`);
    }
    // The private payload must never emit a cleartext control/operation frame
    // over the encrypted stream. The opaque edge relays binary ciphertext only
    // (it closes on `Message::Text`), and the architecture lock requires the
    // operation type to stay inside the AEAD envelope.
    if (
      /\.send\(\s*JSON\.stringify\(/.test(text) ||
      /["']?control["']?\s*:\s*["']resync["']/.test(text)
    ) {
      throw new Error(`payload file ${p} emits a cleartext control frame over the stream`);
    }
  }

  // 7b. Private payload CSP must stay own-origin, forbid object/base, and pin an
  // explicit worker policy. `blob:`/`data:` are permitted ONLY for the
  // build-time-inlined in-memory worker script; no external origin is allowed.
  const payloadHtml = await readFile(join(payloadDist, "index.html"), "utf8");
  const payloadCspMatch = payloadHtml.match(
    /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i,
  );
  if (!payloadCspMatch) {
    throw new Error("payload index.html missing Content-Security-Policy meta tag");
  }
  const payloadCsp = payloadCspMatch[1];
  // Exact-match policy: any added `unsafe-inline`/`unsafe-eval`, dropped
  // worker allowance, or wildcard changes the string and fails the gate.
  const expectedPayloadCsp =
    "default-src 'self'; script-src 'self' blob:; style-src 'self' blob:; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob: data:; object-src 'none'; base-uri 'none'; form-action 'self'";
  if (payloadCsp !== expectedPayloadCsp) {
    throw new Error(
      `payload CSP mismatch:\n  expected: ${expectedPayloadCsp}\n  actual:   ${payloadCsp}`,
    );
  }
  // The private payload's own document metadata must stay neutral too.
  assertNeutralDocumentMetadata(payloadHtml, "payload index.html");
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
  assertCliRejected(sealEmptyAttempt, "empty input file was unexpectedly accepted by seal-artifact");

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
  assertCliRejected(decryptTruncAttempt, "truncated artifact was unexpectedly accepted by decrypt-artifact");

  // 9j. Missing kid fails closed on seal-artifact CLI
  const missingKidSeal = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "seal-artifact", "--",
    "--public-key-b64", publicKey.toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe" });
  assertCliRejected(missingKidSeal, "missing kid was unexpectedly accepted by seal-artifact CLI");

  // 9k. All-zero kid fails closed on seal-artifact CLI
  const zeroKidSeal = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "seal-artifact", "--",
    "--public-key-b64", publicKey.toString("base64"),
    "--kid-b64", Buffer.alloc(16).toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe" });
  assertCliRejected(zeroKidSeal, "all-zero kid was unexpectedly accepted by seal-artifact CLI");

  // 9l. Missing kid fails closed on decrypt-artifact CLI
  const missingKidDecrypt = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "decrypt-artifact", "--",
    "--unlock-secret-b64", unlockSecret.toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe" });
  assertCliRejected(missingKidDecrypt, "missing kid was unexpectedly accepted by decrypt-artifact CLI");

  // 9m. All-zero kid fails closed on decrypt-artifact CLI
  const zeroKidDecrypt = spawnSync("cargo", [
    "run", "--quiet", "-p", "crypto-envelope", "--bin", "decrypt-artifact", "--",
    "--unlock-secret-b64", unlockSecret.toString("base64"),
    "--kid-b64", Buffer.alloc(16).toString("base64"),
    "--input", artifactPath,
    "--output", join(temp, "cli-out.bin"),
  ], { stdio: "pipe" });
  assertCliRejected(zeroKidDecrypt, "all-zero kid was unexpectedly accepted by decrypt-artifact CLI");

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
  const { HandoffGate } = await import("../web/workspace-shell/src/handoff-gate.ts");
  const { UnlockError } = await import("../web/workspace-shell/src/unlock-stages.ts");
  // Capture the fresh per-unlock token the real runtime arms so the live
  // assertions below use the actual injected value. The first arm is the live
  // unlock; the standalone gate checks later re-arm their own instances.
  const capturedHandoffTokens = [];
  const handoffArmOriginal = HandoffGate.prototype.arm;
  HandoffGate.prototype.arm = function (sessionKeys, token) {
    capturedHandoffTokens.push(token);
    return handoffArmOriginal.call(this, sessionKeys, token);
  };

  // The authenticated descriptor supplies the artifact KID and the expected
  // recipient public-key fingerprint; a normal user never types a KID.
  const expectedFingerprint = createHash("sha256").update(publicKey).digest("base64");
  const descriptor = {
    protocol_version: 1,
    artifact_version: ARTIFACT_VERSION,
    artifact_kid_b64: kid.toString("base64"),
    artifact_size: 0,
    artifact_sha256_hex: "",
    package_format_version: 1,
    release_id: "release-test",
    source_sha: "test-sha",
    expected_public_key_fingerprint_b64: expectedFingerprint,
    min_shell_protocol: 1,
    max_shell_protocol: 1,
    enrolled: false,
    enrolled_kid_b64: null,
    enrolled_public_key_fingerprint_b64: null,
  };

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
    unlockSecret,
    descriptor,
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

  // 10f. BR-5 handoff gate: one-shot, token-bound, and disarmed by lock().
  //
  // This is the control that stops a same-origin document which navigated into
  // the frame from harvesting live session keys with a forged ready ping.
  {
    // First prove the *live* runtime (armed by the real unlock above with the
    // freshly generated token) refuses a missing/wrong token and releases the
    // keys exactly once for the real injected token.
    HandoffGate.prototype.arm = handoffArmOriginal;
    const liveHandoffToken = capturedHandoffTokens[0];
    if (typeof liveHandoffToken !== "string" || liveHandoffToken.length === 0) {
      throw new Error("runtime did not arm a handoff token");
    }
    if (runtime.takeSessionKeysForHandoff(undefined) !== null) {
      throw new Error("runtime released keys without a handoff token");
    }
    if (runtime.takeSessionKeysForHandoff("not-the-token") !== null) {
      throw new Error("runtime released keys for a wrong handoff token");
    }
    const liveKeys = runtime.takeSessionKeysForHandoff(liveHandoffToken);
    if (!liveKeys || typeof liveKeys.kid !== "string" || liveKeys.kid.length === 0) {
      throw new Error("runtime did not release keys for the injected handoff token");
    }
    if (runtime.takeSessionKeysForHandoff(liveHandoffToken) !== null) {
      throw new Error("runtime released keys twice for the same unlock");
    }

    // Then exercise every branch of the pure gate, including disarm (which the
    // live runtime cannot reach a second time without a fresh unlock).
    const session = { kid: "kid-test", s2cKeyB64: "s2c-test", c2sKeyB64: "c2s-test" };
    const gate = new HandoffGate();
    // Unarmed: nothing is ever released, not even the right-looking token.
    for (const candidate of [undefined, null, "", "token-1", 0, {}]) {
      if (gate.take(candidate) !== null) throw new Error("unarmed handoff gate released keys");
    }
    gate.arm(session, "token-1");
    // Missing, empty, non-string and wrong tokens are all refused.
    for (const bad of [undefined, null, "", 0, {}, "token-2"]) {
      if (gate.take(bad) !== null) {
        throw new Error(`handoff gate accepted a bad token: ${String(bad)}`);
      }
    }
    // The exact token releases the armed session exactly once.
    if (gate.take("token-1") !== session) throw new Error("handoff gate did not release the armed session");
    if (gate.take("token-1") !== null) throw new Error("handoff gate released twice");
    // Re-arming for the next unlock retires the previous token and resets the
    // one-shot state.
    gate.arm(session, "token-2");
    if (gate.take("token-1") !== null) throw new Error("handoff gate accepted a retired token");
    if (gate.take("token-2") !== session) throw new Error("re-armed handoff gate did not release");
    // Disarming refuses everything until the next arm.
    gate.disarm();
    for (const bad of ["token-2", "token-1", undefined, ""]) {
      if (gate.take(bad) !== null) throw new Error("disarmed handoff gate released keys");
    }
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

  // 10g-bis. A second unlock in the same authenticated session must not
  // re-enroll: the descriptor reports the existing binding, so a reload or a
  // lock/unlock cycle cannot hit the server's enrollment conflict (409).
  {
    let enrollHits = 0;
    const enrolledDescriptor = {
      ...descriptor,
      enrolled: true,
      enrolled_kid_b64: kid.toString("base64"),
      enrolled_public_key_fingerprint_b64: expectedFingerprint,
    };
    const second = await runtime.unlock(unlockSecret, enrolledDescriptor, {
      fetchFn: async (url, init = {}) => {
        if (String(url).includes("/enroll")) {
          enrollHits += 1;
          return { ok: false, status: 409 };
        }
        return mockFetch(url, init);
      },
    });
    if (enrollHits !== 0) {
      throw new Error("second unlock in the same session re-enrolled an already-enrolled key");
    }
    if (!second.htmlUrl.startsWith("blob:")) {
      throw new Error("second unlock did not instantiate the payload");
    }
    runtime.lock();
  }

  // 10h. Negative runtime unlock tests fail closed with no secret leakage
  // Wrong unlock secret
  let unlockFailed = false;
  try {
    await runtime.unlock(
      wrongSecret,
      descriptor,
      {
        fetchFn: mockFetch,
      },
    );
  } catch (e) {
    unlockFailed = true;
    if (String(e).includes(wrongSecret.toString("base64"))) {
      throw new Error("unlock error leaked secret");
    }
    if (!(e instanceof UnlockError) || e.stage !== "U5_ARTIFACT") {
      throw new Error(`wrong secret must fail as U5_ARTIFACT, got ${e?.stage ?? e}`);
    }
  }
  if (!unlockFailed) throw new Error("runtime unlock accepted wrong secret");
  if (runtime.unlocked) throw new Error("runtime should remain locked on failure");
  if (runtime.getActiveUrlCount() !== 0) throw new Error("runtime should have 0 URLs on failure");

  // Wrong kid (descriptor carries a stale/mismatched KID)
  unlockFailed = false;
  try {
    await runtime.unlock(
      unlockSecret,
      { ...descriptor, artifact_kid_b64: Buffer.from(wrongKid).toString("base64") },
      {
        fetchFn: mockFetch,
      },
    );
  } catch (e) {
    unlockFailed = true;
    if (!(e instanceof UnlockError) || e.stage !== "U5_ARTIFACT") {
      throw new Error(`wrong kid must fail as U5_ARTIFACT, got ${e?.stage ?? e}`);
    }
  }
  if (!unlockFailed) throw new Error("runtime unlock accepted wrong kid");
  if (runtime.unlocked) throw new Error("runtime should remain locked on failure");

  // All-zero secret fails closed before network
  unlockFailed = false;
  try {
    await runtime.unlock(
      Buffer.alloc(32),
      descriptor,
      { fetchFn: mockFetch },
    );
  } catch (e) {
    unlockFailed = true;
    if (!(e instanceof UnlockError) || e.stage !== "U2_ENROLL") {
      throw new Error(`all-zero secret must fail as U2_ENROLL, got ${e?.stage ?? e}`);
    }
  }
  if (!unlockFailed) throw new Error("runtime accepted all-zero secret");

  // All-zero kid fails closed before network
  unlockFailed = false;
  try {
    await runtime.unlock(
      unlockSecret,
      { ...descriptor, artifact_kid_b64: Buffer.alloc(16).toString("base64") },
      { fetchFn: mockFetch },
    );
  } catch (e) {
    unlockFailed = true;
    if (!(e instanceof UnlockError) || e.stage !== "U5_ARTIFACT") {
      throw new Error(`all-zero kid must fail as U5_ARTIFACT, got ${e?.stage ?? e}`);
    }
  }
  if (!unlockFailed) throw new Error("runtime accepted all-zero kid");

  // Server enrollment error fails closed
  unlockFailed = false;
  try {
    await runtime.unlock(
      unlockSecret,
      descriptor,
      {
        fetchFn: async (url) => {
          if (url.includes("enroll")) return { ok: false, status: 500 };
          return { ok: true };
        },
      },
    );
  } catch (e) {
    unlockFailed = true;
    if (!(e instanceof UnlockError) || e.stage !== "U2_ENROLL") {
      throw new Error(`enroll 500 must fail as U2_ENROLL, got ${e?.stage ?? e}`);
    }
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
      unlockSecret,
      descriptor,
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
    if (!(e instanceof UnlockError) || e.stage !== "U2_ENROLL") {
      throw new Error(`409 enroll must fail as U2_ENROLL, got ${e?.stage ?? e}`);
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

  // 10i. Typed stage failures for every remaining stage (U1, U3, U4, U5
  // incompatible, U6, U7) so each stage has a focused assertion.
  async function expectUnlockStage(stage, run, reason) {
    try {
      await run();
    } catch (error) {
      if (!(error instanceof UnlockError)) {
        throw new Error(`expected UnlockError for ${stage}, got ${error}`);
      }
      if (error.stage !== stage) {
        throw new Error(`expected stage ${stage}, got ${error.stage}`);
      }
      if (reason && error.reason !== reason) {
        throw new Error(`expected reason ${reason}, got ${error.reason}`);
      }
      return;
    }
    throw new Error(`expected unlock to fail with ${stage}`);
  }

  // U1: injected WASM loader failure.
  await expectUnlockStage(
    "U1_WASM",
    () =>
      runtime.unlock(unlockSecret, descriptor, {
        wasmLoader: async () => {
          throw new Error("wasm unavailable");
        },
        fetchFn: mockFetch,
      }),
    "wasm_unavailable",
  );

  // U3: artifact grant rejected by the server.
  await expectUnlockStage(
    "U3_GRANT",
    () =>
      runtime.unlock(unlockSecret, descriptor, {
        fetchFn: async (url) => {
          const parsed = new URL(url, "https://localhost:8081");
          if (parsed.pathname.includes("enroll")) return { ok: true, status: 200 };
          if (parsed.pathname.includes("grant")) return { ok: false, status: 500 };
          return { ok: false, status: 500 };
        },
      }),
    "grant_rejected",
  );

  // U4: artifact ciphertext delivery rejected.
  await expectUnlockStage(
    "U4_TRANSPORT",
    () =>
      runtime.unlock(unlockSecret, descriptor, {
        fetchFn: async (url) => {
          const parsed = new URL(url, "https://localhost:8081");
          if (parsed.pathname.includes("enroll")) return { ok: true, status: 200 };
          if (parsed.pathname.includes("grant")) {
            const offer = await getBrokerOffer();
            return {
              ok: true,
              status: 200,
              json: async () => ({
                grant_id: "u4-grant",
                kid: offer.offerKid,
                recipient_public_key: offer.offerPk,
              }),
            };
          }
          return { ok: false, status: 500 };
        },
      }),
    "transport_rejected",
  );

  // U5: server-side compatibility rejection (KID/fingerprint mismatch).
  await expectUnlockStage(
    "U5_ARTIFACT",
    () =>
      runtime.unlock(unlockSecret, descriptor, {
        fetchFn: async (url) => {
          const parsed = new URL(url, "https://localhost:8081");
          if (parsed.pathname.includes("enroll")) return { ok: true, status: 200 };
          if (parsed.pathname.includes("grant")) {
            const offer = await getBrokerOffer();
            return {
              ok: true,
              status: 200,
              json: async () => ({
                grant_id: "u5-grant",
                kid: offer.offerKid,
                recipient_public_key: offer.offerPk,
              }),
            };
          }
          return { ok: false, status: 409, json: async () => ({ code: "artifact_incompatible" }) };
        },
      }),
    "artifact_incompatible",
  );

  // U6: the decrypted payload is not a valid workspace package. The inner
  // artifact must be sealed to the workspace key first, otherwise the failure
  // would correctly classify as U5 (artifact decrypt), not U6 (package unpack).
  const notPackagePath = join(temp, "not-a-package.bin");
  const notPackageArtifact = await sealPackage(
    Buffer.from("this is not a workspace package"),
    publicKey,
    kid,
    ARTIFACT_VERSION,
  );
  await writeFile(notPackagePath, notPackageArtifact);
  await expectUnlockStage(
    "U6_PACKAGE",
    () =>
      runtime.unlock(unlockSecret, descriptor, {
        fetchFn: async (url, init = {}) => {
          const parsed = new URL(url, "https://localhost:8081");
          if (parsed.pathname.includes("enroll")) return { ok: true, status: 200 };
          if (parsed.pathname.includes("grant")) {
            const offer = await getBrokerOffer();
            return {
              ok: true,
              status: 200,
              json: async () => ({
                grant_id: "u6-grant",
                kid: offer.offerKid,
                recipient_public_key: offer.offerPk,
              }),
            };
          }
          const body = JSON.parse(init.body || "{}");
          await sealBrokerEnvelope(body.encapsulated_key, notPackagePath, tempEnvelopePath);
          const data = await readFile(tempEnvelopePath);
          return {
            ok: true,
            status: 200,
            arrayBuffer: async () =>
              data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength),
          };
        },
      }),
    "package_invalid",
  );

  // U7: payload instantiation fails (object URL creation unavailable).
  const originalCreateObjectURL = URL.createObjectURL;
  URL.createObjectURL = () => {
    throw new Error("object urls unavailable");
  };
  try {
    await expectUnlockStage(
      "U7_BOOT",
      () => runtime.unlock(unlockSecret, descriptor, { fetchFn: mockFetch }),
      "boot_failed",
    );
  } finally {
    URL.createObjectURL = originalCreateObjectURL;
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
