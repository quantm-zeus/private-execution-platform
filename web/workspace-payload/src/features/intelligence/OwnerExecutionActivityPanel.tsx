import { Show, createEffect, createMemo, type Component, type JSX } from "solid-js";
import type { CapabilityDenial } from "../../core/types";
import { formatAge } from "../../core/format";
import { createCommandResource } from "../../state/command-state";
import { useWorkspace } from "../../state/session";
import { useWorkstation } from "../../state/workstation";
import { Badge, type Tone } from "../../components/ui/primitives";
import { CompactNote, EmptyBlock, ErrorBlock, LoadingBlock } from "../../components/ui/states";
import {
  parseProgressView,
  progressMetrics,
  progressPercent,
  type ProgressView,
} from "../execution/progress-metrics";

const STATE_TONE: Readonly<Record<ProgressView["state"], Tone>> = {
  planning: "muted",
  running: "info",
  halted: "warning",
  completed: "positive",
  failed: "danger",
  unknown: "muted",
};

const STATE_LABEL: Readonly<Record<ProgressView["state"], string>> = {
  planning: "Planning",
  running: "Running",
  halted: "Halted",
  completed: "Completed",
  failed: "Failed",
  unknown: "Unknown",
};

/**
 * Activity > Mine — the READ-ONLY owner/workspace execution status.
 *
 * The only execution read that exists is `get_execution_progress`, which returns
 * the CURRENT execution (or one named by a correlation id); there is no
 * history-list command. So this renders exactly one current-status block plus a
 * permanent, honest history-unavailable row — it never invents historical rows,
 * and it contains no form, submit or configuration control.
 */
export const OwnerExecutionActivityPanel: Component<{ embedded?: boolean }> = (props) => {
  const ws = useWorkspace();
  const station = useWorkstation();
  const progress = createCommandResource<ProgressView | null>(
    ws.command,
    "get_execution_progress",
    {
      ttlMs: 5_000,
      clock: () => ws.nowMs(),
      validate: (value) => parseProgressView(value),
    },
  );

  // `get_execution_progress` is an ungated owner-scoped reconciliation read
  // (BR-9): the server serves it even when `twap` is not advertised, so it must
  // not be hidden behind `twap`. Until the authenticated command channel is
  // installed it surfaces as "awaiting the channel" rather than an unqueried
  // empty ("no execution running").
  const denial = (): CapabilityDenial | null =>
    ws.commandReady()
      ? null
      : { capability: "twap", reason: "Awaiting the authenticated command channel." };

  let requested = false;
  createEffect(() => {
    // Lazy: only read once the Activity tab is actually open (when embedded).
    if (props.embedded && station.dockTab() !== "activity") return;
    if (ws.commandReady() && !requested) {
      requested = true;
      void progress.run();
    }
  });

  const view = createMemo<ProgressView | null>(() => {
    const state = progress.state();
    if (state.kind === "ready" || state.kind === "stale") return state.value;
    if (state.kind === "loading" || state.kind === "error") return state.prior ?? null;
    return null;
  });

  const ageMs = createMemo<number | null>(() => {
    const state = progress.state();
    if (state.kind !== "ready" && state.kind !== "stale") return null;
    return Math.max(0, ws.nowMs() - state.freshness.receivedAtMs + state.freshness.sourceAgeMs);
  });

  const percent = createMemo<number | null>(() => {
    const value = view();
    return value === null ? null : progressPercent(value);
  });

  const errorView = createMemo<JSX.Element | null>(() => {
    const state = progress.state();
    return state.kind === "error" ? <ErrorBlock error={state.error} /> : null;
  });

  const unavailableView = createMemo<JSX.Element | null>(() => {
    const state = progress.state();
    return state.kind === "unavailable" ? (
      <CompactNote label="Execution progress" reason={state.reason} capability={state.capability} />
    ) : null;
  });

  return (
    <div
      class="pane__scroll"
      data-testid="activity-mine"
      tabindex="0"
      aria-label="Owner execution activity"
    >
      <section class="sect" data-testid="mine-current">
        <div class="sect__head">
          <h4 class="sect__title">Current execution</h4>
          <Show when={view()}>
            {(value) => (
              <span class="sect__tools">
                <Badge tone={STATE_TONE[value().state]}>{STATE_LABEL[value().state]}</Badge>
                <Show when={value().kind}>
                  {(kind) => (
                    <Badge tone="muted">
                      {kind() === "twap" ? "Adaptive TWAP" : "RFQ"}
                    </Badge>
                  )}
                </Show>
              </span>
            )}
          </Show>
          <Show
            when={
              (progress.state().kind === "ready" || progress.state().kind === "stale") &&
              view() === null
            }
          >
            <span class="sect__tools">
              <Badge tone="muted">Idle</Badge>
            </span>
          </Show>
        </div>
        <div class="sect__body">
          <Show when={denial()}>
            {(value) => (
              <CompactNote
                label="Execution progress"
                reason={value().reason}
                capability={value().capability}
              />
            )}
          </Show>
          <Show when={denial() === null}>
            <Show when={progress.state().kind === "loading"}>
              <LoadingBlock label="Loading execution status…" />
            </Show>
            {errorView()}
            {unavailableView()}
            <Show
              when={
                (progress.state().kind === "ready" || progress.state().kind === "stale") &&
                view() === null
              }
            >
              <EmptyBlock title="No execution is running for this workspace." />
            </Show>
            <Show when={view()}>{(value) => <ExecutionStatus value={value()} ageMs={ageMs()} percent={percent()} />}</Show>
          </Show>
        </div>
      </section>

      <section class="sect" data-testid="mine-history">
        <div class="sect__head">
          <h4 class="sect__title">Execution history</h4>
        </div>
        <div class="sect__body">
          <CompactNote
            label="Execution history"
            reason="No authoritative execution-history contract is composed. Only the current execution can be read, so no historical rows are shown."
          />
        </div>
      </section>

      <p class="prov">
        This scope is read-only. Starting a TWAP or requesting an RFQ is an execution action, not
        activity — those controls live in the trade ticket's Advanced execution area, behind the same
        fail-closed, idempotency, UNKNOWN-outcome and TRADING_ENABLED gates as any other order.
        Token market events are never mixed into this scope.
      </p>
    </div>
  );
};

const ExecutionStatus: Component<{
  value: ProgressView;
  ageMs: number | null;
  percent: number | null;
}> = (props) => (
  <div class="panel-stack">
    <p class="exec__id">{props.value.executionId ?? "—"}</p>
    <div class="grad grad--exec">
      <Show when={props.percent !== null}>
        <span class="grad__track">
          <span
            class="grad__fill"
            ref={(element) => {
              element.style.width = `${props.percent ?? 0}%`;
            }}
          />
        </span>
      </Show>
      <span class="grad__val">
        {props.percent === null ? "Progress —" : `${props.percent}%`}
      </span>
    </div>
    <dl class="statgrid">
      {progressMetrics(props.value).map((metric) => (
        <div class="statgrid__cell">
          <dt>{metric.label}</dt>
          <dd data-unknown={metric.value === "—" ? "true" : undefined}>{metric.value}</dd>
        </div>
      ))}
    </dl>
    <Show when={props.value.haltReason}>
      {(reason) => (
        <p class="exec__halt">
          <span aria-hidden="true">!</span>
          <span>{reason()}</span>
        </p>
      )}
    </Show>
    <p class="prov">
      Owner-scoped reconciliation read · updated{" "}
      {props.ageMs === null ? "—" : `${formatAge(props.ageMs)} ago`} · this is a current-status
      surface, not a history
    </p>
  </div>
);

export default OwnerExecutionActivityPanel;
