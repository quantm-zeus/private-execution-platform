# Private workspace browser E2E harness

Real headless-Chromium verification of the private payload in `../workspace-payload`, driven by a
mock of the neutral private-API edge that implements the actual wire contract (BR-1/BR-2/BR-3):
AES-256-GCM envelopes with `AAD = kid=<kid>;seq=<sequence>`, a same-origin WebSocket at `/v1/stream`,
and the neutral `/v1/bootstrap`, `/v1/sync`, `/v1/command` paths.

`server.mjs` is the mock edge. Test-only control lives under `/__test__/*` (set session keys, push
encrypted frames, inspect recorded commands/resyncs). It is never part of a product build.

## What it proves

- Encrypted realtime: the Web Worker decrypts sequenced snapshot/delta frames and the main thread
  renders the Canvas chart and depth (no plaintext, no fake data).
- Sequencing: duplicate/replay is ignored; a gap/tamper forces a `/v1/sync` resync and the client
  **recovers to live** on the next authenticated snapshot.
- Command channel: an operation is sealed client-side, decrypted server-side, and the bound response
  is decrypted and rendered; the cleartext envelope carries only `kid/nonce/sequence/ciphertext`.
- Fail-closed: no capability is enabled optimistically on 404/401, and mutations stay disabled with a
  reason while the trading gate is off.
- Privacy: no `localStorage`/`sessionStorage`/cookies/IndexedDB; no DOM XSS from hostile provider text;
  no trading semantics in URL/title/history.
- Accessibility: axe-core reports no `serious`/`critical` violations across the workstation states
  (no token, search results, Market/Limit ticket, each bottom-dock tab, security drawer).
- Workstation layout (`visual.spec.ts`): the post-unlock shell is one 100vw x 100dvh multi-pane
  workstation (top bar + market rail + chart/bottom dock + right ticket). At 1366x768, 1440x900,
  1920x1080 and 1024x720 it asserts no outer scrollbar, every primary pane in-grid and inside the
  viewport, and the collapsed market rail at <=1180px (the ticket stays in-grid). It attaches
  screenshots for the primary states rather than doing pixel-baseline comparison.
- Routing source (W13): the right ticket defaults to Market/OKX, sends `router_preference` only to the
  neutral first-party command contract, invalidates a source-bound preview when the source changes,
  and refuses a silent OKX→Local substitution (`router.spec.ts`).
- Performance budgets: post-auth load `<2s`, realtime visual update `<300ms`, command round trip
  `<100ms` on the local harness (values are logged per run).
- **Shell unlock** (`shell.spec.ts`): the shell derives the workspace key in audited WASM,
  HPKE-unwraps the encrypted artifact, and instantiates the decrypted payload from `blob:` URLs inside a
  `sandbox="allow-scripts allow-same-origin"` frame under the production CSP (same-origin is required
  because a sandboxed opaque document cannot load `blob:` subresources). The specs assert the payload
  boots, fails closed when the private edge is absent, that lock revokes the frame, and that a wrong
  secret never instantiates a payload. `shell-server.mjs` drives the `crypto-envelope`
  `test-session-host` responder; build it first:

  ```bash
  cargo build -p crypto-envelope --bins --example test-session-host
  # or point at a prebuilt target dir:
  E2E_CRYPTO_TARGET=/tmp/e2e-shell-target pnpm --filter @evergreen/e2e test:e2e
  ```

  If the tooling is missing the shell specs **fail the run** (the unlock boundary is a mandatory
  gate; a silent skip would let CI go green with the security-critical path untested). For a local
  run without the Rust tooling only, set `E2E_ALLOW_SKIP=1` to downgrade to an explicit skip.

## Running

```bash
# from the repo root
pnpm build:workspace-payload
pnpm --filter @evergreen/e2e test:e2e          # browsers in the default cache (CI)
pnpm test:e2e                                  # local: browsers under node_modules (PLAYWRIGHT_BROWSERS_PATH=0)
```

Install the browser once:

```bash
pnpm --filter @evergreen/e2e exec playwright install chromium
# CI / root: add --with-deps to install the system libraries
```

### No-root hosts

If the host lacks Chromium's system libraries and you cannot `sudo`, `apt-get download` still works.
Install a browser and a private sysroot, then point `LD_LIBRARY_PATH` at it:

```bash
SYS=/tmp/e2e-sysroot; mkdir -p "$SYS/debs" "$SYS/root"
cd "$SYS/debs"
for p in libnss3 libnspr4 libatk1.0-0t64 libatk-bridge2.0-0t64 libatspi2.0-0t64 \
         libx11-6 libxcb1 libxcomposite1 libxdamage1 libxext6 libxfixes3 libxrandr2 \
         libgbm1 libxkbcommon0 libasound2t64; do apt-get download "$p"; done
for d in *.deb; do dpkg-deb -x "$d" "$SYS/root"; done
LIBPATH=$(find "$SYS/root" -type d -name '*-linux-gnu' | tr '\n' ':')
LD_LIBRARY_PATH="$LIBPATH" pnpm --filter @evergreen/e2e test:e2e
```
