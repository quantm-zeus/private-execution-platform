import { render } from "solid-js/web";
import "./style.css";
import { AppShell } from "./app/AppShell";
import { WorkspaceProvider } from "./state/session";

const root = document.getElementById("root");
if (!root) {
  throw new Error("workspace root element missing");
}

render(
  () => (
    <WorkspaceProvider>
      <AppShell />
    </WorkspaceProvider>
  ),
  root,
);
