import { Show, onCleanup, onMount, type Component } from "solid-js";
import { useWorkstation } from "../../state/workstation";
import { ActionButton } from "../ui/primitives";
import SecurityPanel from "../../features/security/SecurityPanel";

/**
 * On-demand right drawer for session, passkey/recovery, wallet policy and
 * withdrawal. It is never part of the normal unlocked chrome; Esc closes it and
 * focus moves into the dialog on open.
 */
const DrawerContent: Component<{ onClose: () => void }> = (props) => {
  let panelRef: HTMLElement | undefined;

  onMount(() => {
    queueMicrotask(() => panelRef?.focus());
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        event.preventDefault();
        props.onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    onCleanup(() => window.removeEventListener("keydown", onKey));
  });

  return (
    <>
      <button
        type="button"
        class="drawer-backdrop"
        aria-label="Close security and settings"
        onClick={props.onClose}
      />
      <aside
        class="drawer"
        role="dialog"
        aria-modal="true"
        aria-label="Security and settings"
        tabindex="-1"
        ref={(element) => {
          panelRef = element;
        }}
      >
        <div class="drawer__head">
          <h2 class="drawer__title">Security &amp; settings</h2>
          <ActionButton onClick={props.onClose} title="Close security and settings">
            Close
          </ActionButton>
        </div>
        <div class="drawer__body">
          <SecurityPanel />
        </div>
      </aside>
    </>
  );
};

export const SecurityDrawer: Component = () => {
  const station = useWorkstation();
  // `Show` owns the reactivity: a bare `if (!open()) return null` in a Solid
  // component body executes once and would never mount the drawer on open.
  return (
    <Show when={station.securityOpen()}>
      <DrawerContent onClose={() => station.closeSecurity()} />
    </Show>
  );
};

export default SecurityDrawer;
