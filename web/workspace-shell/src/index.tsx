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

  onMount(async () => {
    try {
      await loadWasm();
      setStatus("Workspace crypto boundary ready.");
    } catch {
      setStatus("Workspace unavailable.");
    }
  });

  onCleanup(() => {
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
            src={payloadUrl()}
            title="Workspace Frame"
            style={{ width: "100%", height: "80vh", border: "1px solid #ccc" }}
          />
        </div>
      </Show>
    </main>
  );
}

render(() => <App />, document.getElementById("root")!);
