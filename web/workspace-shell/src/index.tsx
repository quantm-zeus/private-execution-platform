import { render } from "solid-js/web";
import { createSignal, onMount, onCleanup, Show } from "solid-js";
import "./style.css";
import { loadWasm } from "./wasm-loader";
import { defaultRuntime } from "./unlock-runtime";

function App() {
  const [status, setStatus] = createSignal(
    "Private workspace bootstrap initialized.",
  );
  const [secret, setSecret] = createSignal("");
  const [kid, setKid] = createSignal("");
  const [isUnlocked, setIsUnlocked] = createSignal(false);
  const [payloadUrl, setPayloadUrl] = createSignal("");
  const [isProcessing, setIsProcessing] = createSignal(false);
  let frame: HTMLIFrameElement | undefined;

  // Same-document channel with the decrypted payload: the payload may request a
  // lock (destroy session keys + revoke blob URLs) and announce readiness.
  // Only messages originating from our own frame *and* our own origin are
  // honoured, and the ready ping must echo the per-unlock handoff token the
  // shell injected into the payload document: the sandbox permits
  // self-navigation, so a navigated frame could still match `contentWindow`
  // (BR-6 treats the payload as trusted code, but the binding is cheap
  // defense-in-depth against harvesting live session keys).
  const onPayloadMessage = (event: MessageEvent) => {
    if (!frame || event.source !== frame.contentWindow) return;
    if (event.origin !== window.location.origin) return;
    const data = event.data as { type?: unknown; handoff?: unknown } | null;
    if (!data || typeof data !== "object") return;
    if (data.type === "evergreen:lock-request") {
      handleLock();
    } else if (data.type === "evergreen:workspace-ready") {
      setStatus("Workspace ready.");
      deliverSessionKeys(data.handoff);
    }
  };

  /**
   * BR-5 handoff: deliver the directional session keys to the sandboxed payload
   * over the same-document channel only, once per unlock, and only to a document
   * that echoed the per-unlock token. The payload imports them as
   * non-extractable CryptoKeys; they are never persisted or placed in the DOM.
   */
  const deliverSessionKeys = (handoff: unknown) => {
    const target = frame?.contentWindow;
    if (!target) return;
    const keys = defaultRuntime.takeSessionKeysForHandoff(handoff);
    if (!keys) return;
    try {
      target.postMessage(
        {
          type: "evergreen:session-key",
          kid: keys.kid,
          s2cKeyB64: keys.s2cKeyB64,
          c2sKeyB64: keys.c2sKeyB64,
        },
        window.location.origin,
      );
    } catch {
      // Best effort. Without the handoff the payload stays explicitly offline
      // rather than falling back to any cleartext transport.
    }
  };

  onMount(async () => {
    window.addEventListener("message", onPayloadMessage);
    try {
      await loadWasm();
      setStatus("Workspace crypto boundary ready.");
    } catch {
      setStatus("Workspace unavailable.");
    }
  });

  onCleanup(() => {
    window.removeEventListener("message", onPayloadMessage);
    defaultRuntime.lock();
  });

  const handleUnlock = async (e: Event) => {
    e.preventDefault();
    if (isProcessing()) return;

    const secretValue = secret().trim();
    const kidValue = kid().trim();

    if (!secretValue || !kidValue) {
      setStatus("Unlock secret and Key ID required.");
      return;
    }

    setIsProcessing(true);
    setStatus("Unlocking workspace in memory...");

    try {
      const result = await defaultRuntime.unlock(secretValue, kidValue);
      setPayloadUrl(result.htmlUrl);
      setIsUnlocked(true);
      setStatus("Workspace unlocked.");
    } catch {
      setStatus("Workspace unlock failed.");
      defaultRuntime.lock();
    } finally {
      setSecret("");
      setIsProcessing(false);
    }
  };

  const handleLock = () => {
    defaultRuntime.lock();
    setPayloadUrl("");
    setIsUnlocked(false);
    setStatus("Workspace locked.");
  };

  return (
    <main>
      <h1>Workspace</h1>
      <p id="status">{status()}</p>

      <Show
        when={isUnlocked()}
        fallback={
          <form onSubmit={handleUnlock}>
            <div>
              <label for="unlock-secret">Unlock Secret (32-byte base64):</label>
              <input
                id="unlock-secret"
                type="password"
                autocomplete="off"
                placeholder="Enter 32-byte unlock secret"
                value={secret()}
                onInput={(e) => setSecret(e.currentTarget.value)}
                disabled={isProcessing()}
              />
            </div>
            <div>
              <label for="unlock-kid">Key ID (16-byte base64):</label>
              <input
                id="unlock-kid"
                type="text"
                autocomplete="off"
                placeholder="Enter 16-byte Key ID"
                value={kid()}
                onInput={(e) => setKid(e.currentTarget.value)}
                disabled={isProcessing()}
              />
            </div>
            <button type="submit" disabled={isProcessing()}>
              {isProcessing() ? "Unlocking..." : "Unlock Workspace"}
            </button>
          </form>
        }
      >
        <div>
          <button type="button" onClick={handleLock}>
            Lock Workspace
          </button>
          <iframe
            id="workspace-frame"
            ref={(element) => {
              frame = element;
            }}
            src={payloadUrl()}
            title="Workspace Frame"
            // allow-same-origin is required: the decrypted payload document is
            // instantiated from blob: URLs created by this document, and a
            // sandboxed opaque origin cannot load blob: subresources (Chromium
            // "Not allowed to load local resource"). Navigation, popups, modals,
            // forms and downloads stay denied.
            //
            // CAVEAT (BR-6): with `allow-same-origin` this sandbox is an
            // isolation WARNING, not a containment boundary — a same-origin
            // document can remove its own sandbox. Do not treat it as a security
            // control; the payload is trusted code. Real containment requires
            // serving the payload from a distinct origin.
            sandbox="allow-scripts allow-same-origin"
            class="workspace-frame"
          />
        </div>
      </Show>
    </main>
  );
}

render(() => <App />, document.getElementById("root")!);
