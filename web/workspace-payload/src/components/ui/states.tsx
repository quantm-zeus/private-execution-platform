import { createMemo, Show, type Component, type JSX } from "solid-js";
import { formatAge } from "../../core/format";
import { isFresh, ageMs as computeAge, type CapabilityDenial, type DataState, type WorkspaceErrorShape } from "../../core/types";
import { ActionButton, Badge, ReasonNote } from "./primitives";

export const LoadingBlock: Component<{ label?: string }> = (props) => (
  <div class="state-block state-block--loading" role="status" aria-live="polite">
    <span class="spinner" aria-hidden="true" />
    <span>{props.label ?? "Loading…"}</span>
  </div>
);

export const EmptyBlock: Component<{ title: string; detail?: string; action?: JSX.Element }> = (props) => (
  <div class="state-block state-block--empty">
    <p class="state-block__title">{props.title}</p>
    <Show when={props.detail}>
      <p class="state-block__detail">{props.detail}</p>
    </Show>
    <Show when={props.action}>{props.action}</Show>
  </div>
);

export const ErrorBlock: Component<{ error: WorkspaceErrorShape; onRetry?: () => void }> = (props) => {
  const title = () => {
    if (props.error.code === "capability_missing") return "Unavailable";
    if (props.error.code === "auth") return "Not authorized";
    if (props.error.code === "freshness") return "State changed";
    if (props.error.retryable) return "Temporary failure";
    return "Request failed";
  };
  return (
    <div class="state-block state-block--error" role="alert">
      <p class="state-block__title">{title()}</p>
      <p class="state-block__detail">{props.error.message}</p>
      <Show when={props.error.detail}>
        <p class="state-block__meta">{props.error.detail}</p>
      </Show>
      <Show when={props.onRetry && props.error.retryable}>
        <ActionButton onClick={props.onRetry}>Retry</ActionButton>
      </Show>
    </div>
  );
};

export const UnavailableBlock: Component<{ denial: CapabilityDenial | null; detail?: string }> = (props) => (
  <div class="state-block state-block--unavailable">
    <p class="state-block__title">Backend capability missing</p>
    <p class="state-block__detail">
      {props.denial?.reason ?? "This surface needs a backend contract that is not deployed yet."}
    </p>
    <Show when={props.denial}>
      <p class="state-block__meta">
        capability: <code>{props.denial!.capability}</code>
      </p>
    </Show>
    <Show when={props.detail}>
      <p class="state-block__meta">{props.detail}</p>
    </Show>
    <p class="state-block__detail state-block__detail--muted">
      The workspace fails closed: no synthetic value is shown as if it were live.
    </p>
  </div>
);

export const StaleRibbon: Component<{ ageMs?: number; reason?: string }> = (props) => (
  <div class="stale-ribbon" role="status">
    <Badge tone="warning">STALE</Badge>
    <span>
      {props.ageMs === undefined ? "Age unknown" : `Last update ${formatAge(props.ageMs)} ago`}
      {props.reason ? ` · ${props.reason}` : ""}
    </span>
  </div>
);

export const FreshnessBadge: Component<{
  freshness: { receivedAtMs: number; sourceAgeMs: number; ttlMs: number };
  nowMs: number;
}> = (props) => {
  const fresh = () => isFresh({ ...props.freshness, slot: null }, props.nowMs);
  const age = () =>
    Math.max(0, props.nowMs - props.freshness.receivedAtMs + props.freshness.sourceAgeMs);
  return (
    <Badge
      tone={fresh() ? "positive" : "warning"}
      title={`age ${Math.round(age())}ms, ttl ${props.freshness.ttlMs}ms`}
    >
      {fresh() ? "FRESH" : "STALE"} · {formatAge(age())}
    </Badge>
  );
};

interface SurfaceProps<T> {
  state: DataState<T>;
  denial?: CapabilityDenial | null;
  nowMs: number;
  onRetry?: () => void;
  emptyTitle?: string;
  emptyDetail?: string;
  /** Distinct pre-query copy for `idle`; avoids presenting an unqueried empty. */
  idleTitle?: string;
  idleDetail?: string;
  unavailableDetail?: string;
  isEmpty?: (value: T) => boolean;
  children: (value: T, stale: boolean) => JSX.Element;
}

/**
 * Renders a `DataState<T>` uniformly: idle / loading / empty / error /
 * unavailable / ready, marking a value stale when its age exceeds its TTL.
 */
export function AsyncSurface<T>(props: SurfaceProps<T>): JSX.Element {
  const view = createMemo<JSX.Element>(() => {
    const state = props.state;
    switch (state.kind) {
      case "idle":
        // A surface whose capability is missing must never present an
        // unqueried empty ("no alerts"/"no orders") as if it had been loaded.
        if (props.denial) {
          return <UnavailableBlock denial={props.denial} detail={props.unavailableDetail} />;
        }
        if (props.idleTitle || props.idleDetail) {
          return <EmptyBlock title={props.idleTitle ?? "Not started."} detail={props.idleDetail} />;
        }
        return <EmptyBlock title={props.emptyTitle ?? "Nothing loaded yet."} detail={props.emptyDetail} />;
      case "unavailable":
        return <UnavailableBlock denial={props.denial ?? null} detail={props.unavailableDetail} />;
      case "error":
        return <ErrorBlock error={state.error} onRetry={props.onRetry} />;
      case "loading":
        if (state.prior === undefined) return <LoadingBlock />;
        // Prior data is shown while a refresh is in flight: mark it stale so a
        // slow refresh never paints old balances/orders as if they were current.
        return renderValue(state.prior, true, undefined);
      case "ready": {
        const freshness = { ...state.freshness, slot: null };
        return renderValue(
          state.value,
          !isFresh(freshness, props.nowMs),
          computeAge(state.freshness, props.nowMs),
        );
      }
      case "stale":
        return renderValue(state.value, true, computeAge(state.freshness, props.nowMs));
    }
  });

  function renderValue(value: T, stale: boolean, agedMs: number | undefined): JSX.Element {
    if (props.isEmpty?.(value)) {
      return <EmptyBlock title={props.emptyTitle ?? "No data."} detail={props.emptyDetail} />;
    }
    return (
      <div class="async-value" data-stale={stale ? "true" : "false"}>
        <Show when={stale}>
          <StaleRibbon ageMs={agedMs} />
        </Show>
        {props.children(value, stale)}
      </div>
    );
  }

  return <>{view()}</>;
}

/** Small inline note explaining why a control is disabled. */
export const DenialNote: Component<{ denial: CapabilityDenial | null }> = (props) => (
  <Show when={props.denial}>
    <ReasonNote tone="warning">Disabled: {props.denial!.reason}</ReasonNote>
  </Show>
);
