import { render } from "solid-js/web";
// Vendor layout CSS is bundled (same-origin hashed asset, no runtime CDN) and
// imported before the first-party sheet so local overrides win.
import "@klinecharts/pro/dist/klinecharts-pro.css";
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
