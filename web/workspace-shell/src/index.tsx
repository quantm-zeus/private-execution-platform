import { render } from "solid-js/web";
import { createSignal, onMount } from "solid-js";
import "./style.css";
import { loadWasm } from "./wasm-loader";

const [status, setStatus] = createSignal("Private workspace bootstrap initialized.");

function App() {
  onMount(async () => {
    try {
      await loadWasm();
      setStatus("Workspace crypto boundary ready.");
    } catch {
      setStatus("Workspace unavailable.");
    }
  });

  return (
    <main>
      <h1>Workspace</h1>
      <p>{status()}</p>
    </main>
  );
}

render(() => <App />, document.getElementById("root")!);
