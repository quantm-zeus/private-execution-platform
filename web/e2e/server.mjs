// E2E mock of the neutral private-API edge (BR-1/BR-2/BR-3) plus a static host
// for the built private payload. It implements the *real* wire contract:
// generic AEAD envelopes (AES-256-GCM, AAD `kid=<kid>;seq=<sequence>`) over a
// same-origin WebSocket and the neutral /v1/* paths, so the browser E2E exercises
// the actual crypto/sequencing code rather than a stub.
//
// Test control lives under /__test__/* and is never part of the product.

import { createServer } from "node:http";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";

const here = fileURLToPath(new URL(".", import.meta.url));
const DIST = process.env.E2E_PAYLOAD_DIST
  ? resolve(process.env.E2E_PAYLOAD_DIST)
  : resolve(here, "../workspace-payload/dist");
const PORT = Number(process.env.E2E_PORT ?? 4319);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".wasm": "application/wasm",
};

// Mirrors the payload's own CSP (web/workspace-payload/index.html meta tag).
const PAYLOAD_CSP =
  "default-src 'self'; script-src 'self' blob:; style-src 'self' blob:; img-src 'self' data: blob:; font-src 'self'; " +
  "connect-src 'self'; worker-src 'self' blob: data:; object-src 'none'; base-uri 'none'; form-action 'self'";

const DEFAULT_BOOTSTRAP = {
  protocol_version: 1,
  capabilities: {
    market: true,
    realtime: true,
    quotes: true,
    preview: true,
    execute: true,
    limits: true,
    portfolio: true,
    intelligence: true,
    twitter: true,
    gmgn: true,
    okx: true,
    twap: true,
    rfq: true,
    withdraw: true,
    wallet_limits: true,
  },
  trading_enabled: true,
  kill_switch: { enabled: false, reason: null },
  // BR-11: the chain advertises its quote/native token so the market ticket can
  // resolve the non-selected leg and reach a preview.
  chains: [{ id: "base", display: "Base", enabled: true, native_token: "USDC" }],
  session: { key_id: "kid-e2e", expires_at_ms: 4_000_000_000_000 },
  server_time_ms: 1_700_000_000_000,
};

function freshState() {
  return {
    kid: null,
    s2cKey: null,
    c2sKey: null,
    seq: 0,
    lastEnvelope: null,
    resyncCount: 0,
    socketCount: 0,
    commands: [],
    events: [],
    bootstrap: DEFAULT_BOOTSTRAP,
    commandResponse: { result: { ok: true } },
    // W14: a small authoritative wallet-limit policy so the browser test can
    // exercise a real apply-then-verify flow through the neutral contract.
    walletLimits: {
      wallet_ref: "0xwallet-e2e",
      max_trade_usd: 5_000,
      hourly_turnover_usd: 20_000,
      daily_turnover_usd: 100_000,
      max_buy_tax_bps: 500,
      max_sell_tax_bps: 400,
      max_price_impact_bps: 150,
      max_slippage_bps: 100,
      allowed_chains: ["base"],
      allowed_routers: ["okx"],
      allowed_programs: ["0xrouter"],
      source_age_ms: 0,
      slot: 1,
    },
  };
}

let state = freshState();
const sockets = new Set();
const wss = new WebSocketServer({ noServer: true });

function aad(kid, seq) {
  return Buffer.from(`kid=${kid};seq=${seq}`, "utf8");
}

export function seal(kid, seq, key, value) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad(kid, seq));
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return {
    kid,
    nonce: nonce.toString("base64"),
    sequence: seq,
    ciphertext: ciphertext.toString("base64"),
  };
}

export function openEnvelope(kid, seq, key, envelopeBase64) {
  const nonce = Buffer.from(envelopeBase64.nonce, "base64");
  const raw = Buffer.from(envelopeBase64.ciphertext, "base64");
  const tag = raw.subarray(raw.length - 16);
  const body = raw.subarray(0, raw.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad(kid, seq));
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

/** Opaque AEAD response: the bare envelope as UTF-8 JSON octet-stream bytes. */
function octetStream(res, status, envelope) {
  const payload = Buffer.from(JSON.stringify(envelope), "utf8");
  res.writeHead(status, {
    "Content-Type": "application/octet-stream",
    "Cache-Control": "no-store",
    "Content-Length": payload.length,
  });
  res.end(payload);
}

function readRawBody(req, limit = 2 * 1024 * 1024) {
  return new Promise((resolvePromise, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolvePromise(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/**
 * Decode an octet-stream request: parse the generic envelope, validate the kid
 * and open it with the seeded c2s key. Returns `null` (never throws) so a
 * hostile body cannot take down the mock.
 */
async function readEnvelopeRequest(req) {
  if (!state.kid || !state.c2sKey) return null;
  let envelope;
  try {
    envelope = JSON.parse((await readRawBody(req)).toString("utf8"));
  } catch {
    return null;
  }
  if (!envelope || typeof envelope !== "object" || envelope.kid !== state.kid) return null;
  try {
    const plaintext = openEnvelope(state.kid, envelope.sequence, state.c2sKey, envelope);
    return { envelope, plaintext };
  } catch {
    return null;
  }
}

function readBody(req, limit = 2 * 1024 * 1024) {
  return new Promise((resolvePromise, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (chunks.length === 0) return resolvePromise({});
      try {
        resolvePromise(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new Error("invalid json"));
      }
    });
    req.on("error", reject);
  });
}

async function serveStatic(req, res) {
  const url = new URL(req.url ?? "/", "http://localhost");
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === "/" || pathname === "") pathname = "/index.html";
  const relative = normalize(pathname).replace(/^([/\\])+/, "");
  const target = resolve(DIST, relative);
  if (target !== DIST && !target.startsWith(DIST + sep)) {
    res.writeHead(403).end("forbidden");
    return;
  }
  try {
    const data = await readFile(target);
    const type = MIME[extname(target)] ?? "application/octet-stream";
    res.writeHead(200, {
      "Content-Type": type,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": PAYLOAD_CSP,
    });
    res.end(data);
  } catch {
    // SPA fallback for in-memory navigation. Carry the same security headers as
    // a real asset response so a CSP regression cannot hide behind the fallback.
    try {
      const data = await readFile(join(DIST, "index.html"));
      res.writeHead(200, {
        "Content-Type": MIME[".html"],
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": PAYLOAD_CSP,
      });
      res.end(data);
    } catch {
      res.writeHead(404).end("not found");
    }
  }
}

function broadcast(envelope) {
  const text = JSON.stringify(envelope);
  state.lastEnvelope = envelope;
  for (const socket of sockets) {
    // The real opaque edge relays binary frames only (it closes on any text
    // frame), so the mock must push binary too for the client to be exercised
    // against the production framing.
    if (socket.readyState === 1) socket.send(Buffer.from(text, "utf8"));
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;

  try {
    if (path === "/v1/bootstrap" && req.method === "POST") {
      const opened = await readEnvelopeRequest(req);
      if (!opened) {
        json(res, 400, { error: "unavailable" });
        return;
      }
      // The bootstrap response is the flat workspace-session document the web
      // parser accepts, plus the request-id echo (BR-3). `session.key_id` must
      // equal the wire kid exactly as the real private API derives it.
      const document = {
        ...state.bootstrap,
        session: { ...(state.bootstrap.session ?? {}), key_id: state.kid },
        request_id: opened.plaintext.request_id,
      };
      const envelope = seal(state.kid, opened.envelope.sequence, state.s2cKey, document);
      octetStream(res, 200, envelope);
      return;
    }

    if (path === "/v1/sync" && req.method === "POST") {
      const opened = await readEnvelopeRequest(req);
      if (!opened) {
        json(res, 400, { error: "unavailable" });
        return;
      }
      state.resyncCount += 1;
      const responseBody = {
        request_id: opened.plaintext.request_id,
        result: { accepted: true, from_seq: opened.plaintext.from_seq ?? null },
      };
      const envelope = seal(state.kid, opened.envelope.sequence, state.s2cKey, responseBody);
      octetStream(res, 200, envelope);
      return;
    }

    if (path === "/v1/command" && req.method === "POST") {
      const opened = await readEnvelopeRequest(req);
      if (!opened) {
        json(res, 503, { error: "session unavailable" });
        return;
      }
      const oper = opened.plaintext;
      state.commands.push({
        op: oper.op,
        payload: oper.payload,
        sequence: opened.envelope.sequence,
        requestId: oper.request_id,
      });
      // Echo the per-request challenge inside the AEAD: the client binds the
      // response to its request, so a captured stream frame or a replayed older
      // command response cannot be substituted.
      let responseBody;
      if (oper.op === "get_wallet_limits") {
        responseBody = { result: state.walletLimits, request_id: oper.request_id };
      } else if (oper.op === "set_wallet_limits") {
        const patch = oper.payload && typeof oper.payload === "object" ? oper.payload : {};
        state.walletLimits = { ...state.walletLimits, ...patch, source_age_ms: 0 };
        responseBody = { result: { ok: true }, request_id: oper.request_id };
      } else {
        responseBody = { ...state.commandResponse, request_id: oper.request_id };
      }
      const envelope = seal(state.kid, opened.envelope.sequence, state.s2cKey, responseBody);
      octetStream(res, 200, envelope);
      return;
    }

    if (path === "/__test__/session" && req.method === "POST") {
      const body = await readBody(req);
      state.kid = body.kid;
      state.s2cKey = Buffer.from(body.s2cKeyB64, "base64");
      state.c2sKey = body.c2sKeyB64 ? Buffer.from(body.c2sKeyB64, "base64") : null;
      state.seq = 0;
      state.lastEnvelope = null;
      json(res, 200, { ok: true });
      return;
    }

    if (path === "/__test__/bootstrap" && req.method === "POST") {
      state.bootstrap = (await readBody(req)).bootstrap ?? DEFAULT_BOOTSTRAP;
      json(res, 200, { ok: true });
      return;
    }

    if (path === "/__test__/command-response" && req.method === "POST") {
      state.commandResponse = (await readBody(req)).response ?? { result: { ok: true } };
      json(res, 200, { ok: true });
      return;
    }

    if (path === "/__test__/send" && req.method === "POST") {
      const body = await readBody(req);
      if (!state.kid || !state.s2cKey) {
        json(res, 503, { error: "session unavailable" });
        return;
      }
      const sent = [];
      if (body.replay) {
        if (state.lastEnvelope) broadcast(state.lastEnvelope);
        json(res, 200, { sent: state.lastEnvelope ? [state.lastEnvelope] : [] });
        return;
      }
      if (body.raw) {
        const envelope = { kid: state.kid, ...body.raw };
        broadcast(envelope);
        json(res, 200, { sent: [envelope] });
        return;
      }
      if (typeof body.skip === "number" && body.skip > 0) {
        state.seq += body.skip;
      }
      for (const frame of body.frames ?? []) {
        const envelope = seal(state.kid, state.seq, state.s2cKey, frame);
        state.seq += 1;
        if (body.tamper) {
          const raw = Buffer.from(envelope.ciphertext, "base64");
          raw[0] ^= 0xff;
          envelope.ciphertext = raw.toString("base64");
        }
        broadcast(envelope);
        sent.push(envelope);
      }
      json(res, 200, { sent });
      return;
    }

    if (path === "/__test__/axe.min.js" && req.method === "GET") {
      // Served same-origin so the payload CSP (`script-src 'self'`) permits it;
      // addScriptTag({ path }) would inject inline and be blocked.
      const axePath = fileURLToPath(new URL("./node_modules/axe-core/axe.min.js", import.meta.url));
      const data = await readFile(axePath);
      res.writeHead(200, {
        "Content-Type": "text/javascript; charset=utf-8",
        "Cache-Control": "no-store",
      });
      res.end(data);
      return;
    }

    if (path === "/__test__/close-sockets" && req.method === "POST") {      const count = sockets.size;
      for (const socket of sockets) socket.close();
      json(res, 200, { closed: count });
      return;
    }

    if (path === "/__test__/state" && req.method === "GET") {
      json(res, 200, {
        resyncCount: state.resyncCount,
        socketCount: state.socketCount,
        activeSockets: sockets.size,
        commands: state.commands,
        events: state.events,
      });
      return;
    }

    if (path === "/__test__/reset" && req.method === "POST") {
      for (const socket of sockets) socket.close();
      sockets.clear();
      state = freshState();
      json(res, 200, { ok: true });
      return;
    }

    if (path.startsWith("/v1/")) {
      json(res, 404, { error: "not found" });
      return;
    }

    await serveStatic(req, res);
  } catch (error) {
    json(res, 400, { error: error instanceof Error ? error.message : "bad request" });
  }
});

server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname !== "/v1/stream") {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    sockets.add(ws);
    state.socketCount += 1;
    state.events.push({ type: "socket-open" });
    ws.on("message", (data, isBinary) => {
      // The production opaque edge relays **binary** ciphertext and closes on
      // any text frame. The worker sends exactly one binary AEAD `subscribe`
      // frame per (re)connect (BR-2), so a binary frame is expected; a text
      // control frame is the regression the browser suite fails on.
      if (!isBinary) {
        let message = null;
        try {
          message = JSON.parse(data.toString("utf8"));
        } catch {
          message = data.toString("utf8").slice(0, 200);
        }
        state.events.push({ type: "socket-text-frame", message });
        try {
          ws.close();
        } catch {
          // already closed
        }
        return;
      }
      state.events.push({ type: "socket-binary-frame" });
    });
    ws.on("close", () => {
      sockets.delete(ws);
      state.events.push({ type: "socket-close" });
    });
    ws.on("error", () => {
      sockets.delete(ws);
    });
  });
});

server.listen(PORT, "127.0.0.1", () => {
  // eslint-disable-next-line no-console
  console.log(`e2e mock private edge listening on http://127.0.0.1:${PORT} (dist: ${DIST})`);
});
