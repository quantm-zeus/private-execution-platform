import { render } from "solid-js/web";
import "./style.css";

function App() {
  return (
    <main>
      <h1>Workspace</h1>
      <p>Private workspace payload execution.</p>
    </main>
  );
}

render(() => <App />, document.getElementById("root")!);
