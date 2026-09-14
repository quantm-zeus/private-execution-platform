import { For, Show, type Component, type JSX } from "solid-js";

export type Tone = "neutral" | "positive" | "warning" | "danger" | "info" | "muted";

export const Badge: Component<{
  tone?: Tone;
  children: JSX.Element;
  title?: string;
}> = (props) => (
  <span class={`badge badge--${props.tone ?? "neutral"}`} title={props.title}>
    {props.children}
  </span>
);

export const StatusDot: Component<{ tone: Tone; label: string }> = (props) => (
  <span class={`status-dot status-dot--${props.tone}`} role="img" aria-label={props.label} />
);

export const Panel: Component<{
  title: string;
  subtitle?: string;
  actions?: JSX.Element;
  badge?: JSX.Element;
  children: JSX.Element;
  class?: string;
}> = (props) => (
  <section class={`panel ${props.class ?? ""}`} aria-label={props.title}>
    <header class="panel__head">
      <div class="panel__titles">
        <h2 class="panel__title">{props.title}</h2>
        <Show when={props.subtitle}>
          <p class="panel__subtitle">{props.subtitle}</p>
        </Show>
      </div>
      <div class="panel__actions">
        {props.badge}
        {props.actions}
      </div>
    </header>
    <div class="panel__body">{props.children}</div>
  </section>
);

export const Metric: Component<{
  label: string;
  value: JSX.Element;
  hint?: string;
  tone?: Tone;
}> = (props) => (
  <div class={`metric metric--${props.tone ?? "neutral"}`}>
    <span class="metric__label">{props.label}</span>
    <span class="metric__value">{props.value}</span>
    <Show when={props.hint}>
      <span class="metric__hint">{props.hint}</span>
    </Show>
  </div>
);

export const MetricGrid: Component<{ children: JSX.Element; columns?: number }> = (props) => (
  <div
    class="metric-grid"
    style={props.columns ? { "grid-template-columns": `repeat(${props.columns}, minmax(0, 1fr))` } : undefined}
  >
    {props.children}
  </div>
);

export const Field: Component<{
  label: string;
  hint?: string;
  error?: string;
  children: JSX.Element;
  forId?: string;
}> = (props) => (
  <div class="field">
    <label class="field__label" for={props.forId}>
      {props.label}
    </label>
    {props.children}
    <Show when={props.hint}>
      <p class="field__hint">{props.hint}</p>
    </Show>
    <Show when={props.error}>
      <p class="field__error" role="alert">
        {props.error}
      </p>
    </Show>
  </div>
);

export const ReasonNote: Component<{ tone?: Tone; children: JSX.Element }> = (props) => (
  <p class={`reason-note reason-note--${props.tone ?? "warning"}`}>{props.children}</p>
);

/** A row of key/value evidence used by economics and evidence surfaces. */
export const KeyValue: Component<{
  rows: readonly { key: string; label: string; value: JSX.Element; tone?: Tone }[];
}> = (props) => (
  <dl class="key-value">
    <For each={props.rows}>
      {(row) => (
        <div class="key-value__row" data-key={row.key}>
          <dt>{row.label}</dt>
          <dd class={row.tone ? `text--${row.tone}` : undefined}>{row.value}</dd>
        </div>
      )}
    </For>
  </dl>
);

export const ActionButton: Component<
  {
    onClick?: () => void;
    disabled?: boolean;
    tone?: "primary" | "danger" | "ghost";
    title?: string;
    type?: "button" | "submit";
    children: JSX.Element;
  }
> = (props) => (
  <button
    type={props.type ?? "button"}
    class={`btn btn--${props.tone ?? "ghost"}`}
    onClick={props.onClick}
    disabled={props.disabled}
    title={props.title}
  >
    {props.children}
  </button>
);
