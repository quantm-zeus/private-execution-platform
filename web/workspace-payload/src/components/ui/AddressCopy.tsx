import { Show, createSignal, onCleanup, type Component } from "solid-js";
import { truncateAddress } from "../../core/format";

/**
 * Accessible copy control for an exact token address.
 *
 * It copies the full address verbatim (never a truncated or normalized form)
 * and announces a transient "Copied" state. It never touches clipboard APIs
 * that could expose secrets: only the public on-chain address is written, and
 * an unavailable clipboard degrades to a no-op rather than throwing.
 */
export const AddressCopy: Component<{
  address: string;
  chain?: string;
  class?: string;
}> = (props) => {
  const [copied, setCopied] = createSignal(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const clearTimer = (): void => {
    if (timer !== undefined) {
      clearTimeout(timer);
      timer = undefined;
    }
  };
  onCleanup(clearTimer);

  const copy = (): void => {
    const clipboard = typeof navigator !== "undefined" ? navigator.clipboard : undefined;
    if (!clipboard || typeof clipboard.writeText !== "function") return;
    void clipboard
      .writeText(props.address)
      .then(() => {
        setCopied(true);
        clearTimer();
        timer = setTimeout(() => setCopied(false), 1_600);
      })
      .catch(() => {
        // Clipboard permission denied: no false "Copied" feedback.
        setCopied(false);
      });
  };

  return (
    <button
      type="button"
      class={`address-copy ${props.class ?? ""}`}
      onClick={copy}
      title={props.address}
      aria-label={`Copy ${props.chain ? `${props.chain} ` : ""}address ${props.address}`}
    >
      <code class="address-copy__value">{truncateAddress(props.address, 6, 6)}</code>
      <Show
        when={copied()}
        fallback={
          <span class="address-copy__hint" aria-hidden="true">
            copy
          </span>
        }
      >
        <span class="address-copy__done" role="status" data-testid="address-copied">
          Copied
        </span>
      </Show>
    </button>
  );
};

export default AddressCopy;
