import { Show, type Component } from "solid-js";

/**
 * One primitive, two content types: a real provider-supplied token logo, or a
 * typographic monogram when the provider supplies none — and *always* for a
 * trader, whose avatar is a third party's photograph and is never fabricated.
 *
 * `cover`, not `contain`: the real marks arrive with transparent, dark, light and
 * photographic backgrounds, and cover gives every one the same hard tile edge.
 * A hostile `src` is a text/URL value, not markup, and only http(s) URLs are
 * passed by the caller (see `safeHttpUrl`).
 */
export const MarkTile: Component<{
  symbol: string;
  src?: string | null;
  /** Explicit monogram override; defaults to the first three symbol characters. */
  monogram?: string;
  size?: "md" | "sm";
  title?: string;
}> = (props) => {
  const monogram = (): string => {
    if (props.monogram !== undefined) return props.monogram.slice(0, 3).toUpperCase();
    const raw = (props.symbol || "?").replace(/^@/, "").trim();
    return raw.slice(0, 3).toUpperCase() || "?";
  };
  return (
    <span
      class={`mark-tile${props.size === "sm" ? " mark-tile--sm" : ""}`}
      title={props.title}
      aria-hidden="true"
    >
      <Show
        when={props.src}
        fallback={<span class="mark-tile__mono">{monogram()}</span>}
      >
        {(src) => <img src={src()} width="64" height="64" alt="" loading="lazy" />}
      </Show>
    </span>
  );
};

export default MarkTile;
