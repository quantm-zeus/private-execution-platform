import type { Component } from "solid-js";
import { useWorkstation } from "../../state/workstation";

/**
 * The pane-bar dock expand control. It is a plain button (never inside the
 * `role="tablist"`, which may contain only tabs) and it is memory-only.
 */
export const DockExpandButton: Component = () => {
  const station = useWorkstation();
  const expanded = () => station.dockExpanded();
  return (
    <button
      type="button"
      class="btn btn--sm"
      data-testid="intel-dock-expand"
      aria-expanded={expanded()}
      title={expanded() ? "Collapse the data dock" : "Expand the data dock"}
      onClick={() => station.toggleDockExpanded()}
    >
      {expanded() ? "Collapse" : "Expand"}
    </button>
  );
};

export default DockExpandButton;
