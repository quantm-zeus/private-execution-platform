import { Show, createMemo, createSignal, type Component } from "solid-js";
import { useWorkstation } from "../../state/workstation";
import { useWorkspace } from "../../state/session";
import { DockExpandButton } from "../../components/layout/DockExpandButton";
import { TokenActivity } from "./TokenActivity";
import { OwnerExecutionActivityPanel } from "./OwnerExecutionActivityPanel";

export type ActivityScope = "token" | "mine";

/**
 * Activity — the single home for chronological event streams.
 *
 * It owns two scopes and the scope selector is the provenance switch:
 *   Token  the exact selected token's market event stream
 *   Mine   the READ-ONLY owner/workspace execution status
 *
 * They are never interleaved and never share a row style, and there is no path
 * from this tab to a mutating execution control.
 */
export const ActivityWorkspace: Component<{ embedded?: boolean }> = (props) => {
  const station = useWorkstation();
  const ws = useWorkspace();
  // null = the operator has not chosen; the workspace decides. An explicit
  // choice always wins and survives an instrument switch.
  const [chosen, setChosen] = createSignal<ActivityScope | null>(null);

  const scope = createMemo<ActivityScope>(() => {
    const explicit = chosen();
    if (explicit !== null) return explicit;
    // Token when an exact token is selected and its activity read is composed;
    // Mine otherwise. This is a capability statement, not a data guess.
    return station.intelKey() !== null && station.intelDenial() === null ? "token" : "mine";
  });

  const meta = createMemo(() =>
    scope() === "token"
      ? `${ws.selectedInstrument()?.symbol ?? "—"} · exact token`
      : "owner workspace",
  );

  return (
    <section class="pane" data-testid="activity-pane">
      <div class="pane__bar">
        <h3 class="pane__title">Activity</h3>
        <span class="pane__meta">{meta()}</span>
        <span class="pane__tools">
          <div class="seg" role="group" aria-label="Activity scope">
            <button
              type="button"
              class="seg__btn"
              data-testid="activity-scope-token"
              aria-pressed={scope() === "token"}
              title="Market events for the selected token"
              onClick={() => setChosen("token")}
            >
              Token
            </button>
            <button
              type="button"
              class="seg__btn"
              data-testid="activity-scope-mine"
              aria-pressed={scope() === "mine"}
              title="Your own execution activity"
              onClick={() => setChosen("mine")}
            >
              Mine
            </button>
          </div>
          <DockExpandButton />
        </span>
      </div>
      <Show when={scope() === "token"} fallback={<OwnerExecutionActivityPanel embedded={props.embedded} />}>
        <TokenActivity embedded={props.embedded} />
      </Show>
    </section>
  );
};

export default ActivityWorkspace;
