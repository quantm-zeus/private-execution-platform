import { render } from "solid-js/web";
import { createSignal } from "solid-js";
import "./style.css";
import { BootstrapError, bootstrapArtifact } from "./bootstrap";

const [status, setStatus] = createSignal("Private workspace bootstrap boundary.");

async function start() {
  setStatus("Requesting artifact…");
  try {
    const { envelope } = await bootstrapArtifact();
    // Decryption is the remaining fail-closed seam (see bootstrap.ts header).
    // Until the audited browser HPKE/AEAD implementation lands, we surface
    // only the fact that the transport phase succeeded, and never touch the
    // ciphertext beyond holding it in memory.
    setStatus(`Artifact envelope received (${envelope.ciphertext.length} bytes). Decryption pending audited client implementation.`);
  } catch (error) {
    if (error instanceof BootstrapError) {
      setStatus("Workspace unavailable.");
    } else {
      setStatus("Workspace unavailable.");
    }
  }
}

void start();

function App() {
  return (
    <main>
      <h1>Workspace</h1>
      <p>{status()}</p>
    </main>
  );
}

render(() => <App />, document.getElementById("root")!);
