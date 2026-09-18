import { Show, createEffect, createSignal, onCleanup, onMount, type Component } from "solid-js";
import { Portal } from "solid-js/web";
import { ActionButton } from "../../components/ui/primitives";
import ExecutionPanel from "./ExecutionPanel";

/**
 * The trade ticket's Advanced execution entry point and drawer.
 *
 * Adaptive TWAP and RFQ are execution ACTIONS, so they live here — in the trade
 * ticket's Advanced execution area, behind the same fail-closed, idempotency,
 * UNKNOWN-outcome and TRADING_ENABLED gates as any other order. They are never
 * reachable from the Activity tab.
 *
 * The drawer copies the SecurityDrawer pattern (`role="dialog"`, `aria-modal`,
 * `aria-labelledby`, `tabindex="-1"`, Escape closes, focus returns to the
 * invoking control) and is portalled so its forms are never nested inside the
 * ticket's own form element.
 *
 * IMPORTANT: the panel is hidden, never unmounted. Its submission-key tracker and
 * UNKNOWN-outcome guards are component-local, so unmounting on close would
 * silently release an unresolved UNKNOWN and let a duplicate order through.
 */
const DrawerContent: Component<{ open: boolean; onClose: () => void }> = (props) => {
  let dialogRef: HTMLElement | undefined;

  onMount(() => {
    const onKey = (event: KeyboardEvent): void => {
      if (!props.open) return;
      if (event.key === "Escape") {
        event.preventDefault();
        props.onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    onCleanup(() => window.removeEventListener("keydown", onKey));
  });

  createEffect(() => {
    if (props.open) queueMicrotask(() => dialogRef?.focus());
  });

  return (
    <>
      <button
        type="button"
        class="drawer-backdrop"
        hidden={!props.open}
        aria-label="Close advanced execution"
        onClick={props.onClose}
      />
      <aside
        class="drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="advanced-execution-title"
        aria-hidden={!props.open}
        hidden={!props.open}
        tabindex="-1"
        ref={(element) => {
          dialogRef = element;
        }}
      >
        <div class="drawer__head">
          <h2 class="drawer__title" id="advanced-execution-title">
            Advanced execution
          </h2>
          <ActionButton onClick={props.onClose} title="Close advanced execution">
            Close
          </ActionButton>
        </div>
        <div class="drawer__body">
          <ExecutionPanel />
        </div>
      </aside>
    </>
  );
};

export const AdvancedExecutionDrawer: Component = () => {
  const [open, setOpen] = createSignal(false);
  // Mount on first open and keep mounted afterwards: the panel's UNKNOWN and
  // idempotency guards must survive a close, but nothing should be fetched
  // before the operator asks for it.
  const [everOpened, setEverOpened] = createSignal(false);
  let invoker: HTMLButtonElement | undefined;

  const close = (): void => {
    setOpen(false);
    // Focus returns to the control that opened the drawer.
    queueMicrotask(() => invoker?.focus());
  };

  return (
    <>
      <button
        type="button"
        class="btn"
        data-testid="advanced-execution-open"
        aria-haspopup="dialog"
        aria-expanded={open()}
        title="Open adaptive TWAP and RFQ execution controls"
        ref={(element) => {
          invoker = element;
        }}
        onClick={() => {
          setEverOpened(true);
          setOpen(true);
        }}
      >
        Advanced execution
      </button>
      <Portal>
        <Show when={everOpened()}>
          <DrawerContent open={open()} onClose={close} />
        </Show>
      </Portal>
    </>
  );
};

export default AdvancedExecutionDrawer;
