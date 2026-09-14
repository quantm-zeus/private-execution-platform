import { Show, createMemo, createSignal, type Component } from "solid-js";
import { formatAmount, formatBps, formatPercent } from "../../core/format";
import type { WorkspaceErrorShape } from "../../core/types";
import type { ExecutionProgress, RfqLegView, RfqView, TwapRequest } from "../../contracts/execution";
import { createCommandResource } from "../../state/command-state";
import { useWorkspace } from "../../state/session";
import { ActionButton, Badge, Metric, MetricGrid, Panel, ReasonNote } from "../../components/ui/primitives";
import { AsyncSurface, DenialNote, EmptyBlock, ErrorBlock } from "../../components/ui/states";

function num(raw: string): number | null {
  const value = Number(raw.trim());
  return Number.isFinite(value) && value > 0 ? value : null;
}

function progressMetrics(progress: ExecutionProgress) {
  const done = progress.chunksDone;
  const total = progress.chunksTotal;
  return [
    { label: "State", value: progress.state.toUpperCase() },
    { label: "Chunks", value: total === null ? "—" : `${done ?? 0}/${total}` },
    { label: "Filled", value: progress.filledAmount ?? "—" },
    { label: "Remaining", value: progress.remainingAmount ?? "—" },
    { label: "Realized vs estimate", value: formatBps(progress.realizedVsEstimateBps) },
    { label: "Progress", value: total && done !== null ? formatPercent(done / total) : "—" },
  ];
}

export const ExecutionPanel: Component = () => {
  const ws = useWorkspace();
  const [amount, setAmount] = createSignal("");
  const [slippage, setSlippage] = createSignal("100");
  const [impact, setImpact] = createSignal("150");
  const [interval, setInterval] = createSignal("30000");
  const [maxChunks, setMaxChunks] = createSignal("6");
  const [twapState, setTwapState] = createSignal<ExecutionProgress | null>(null);
  const [twapError, setTwapError] = createSignal<WorkspaceErrorShape | null>(null);
  const progress = createCommandResource<ExecutionProgress>(ws.command, "get_execution_progress", {
    capability: "twap",
    ttlMs: 5_000,
  });
  const rfq = createCommandResource<RfqView>(ws.command, "submit_rfq", {
    capability: "rfq",
    ttlMs: 10_000,
  });

  const twapDenial = createMemo(() => ws.mutationDenial("twap"));
  const rfqDenial = createMemo(() => ws.mutationDenial("rfq"));
  const twapValid = createMemo(
    () => num(amount()) !== null && num(slippage()) !== null && num(impact()) !== null,
  );

  const startTwap = async () => {
    if (!twapValid()) return;
    const chainId = ws.session()?.chains.find((chain) => chain.enabled)?.id ?? "base";
    const request: TwapRequest = {
      chain: chainId,
      tokenIn: "",
      tokenOut: "",
      side: "buy",
      totalAmount: amount(),
      amountType: "usd",
      maxSlippageBps: Math.round(num(slippage())!),
      maxPriceImpactBps: Math.round(num(impact())!),
      intervalMs: Math.round(num(interval()) ?? 30_000),
      maxChunks: Math.round(num(maxChunks()) ?? 6),
    };
    // Deterministic per logical submission so a manual retry is idempotent and
    // can never create a duplicate TWAP; a changed input yields a new key.
    const idempotencyKey = `twap-${chainId}-${amount()}-${slippage()}-${impact()}-${interval()}-${maxChunks()}`;
    setTwapError(null);
    try {
      const result = await ws.command.send<ExecutionProgress>("start_twap", request, {
        idempotencyKey,
      });
      setTwapState(result);
    } catch (error) {
      const shape = (error as { toShape?: () => WorkspaceErrorShape }).toShape?.() ?? {
        code: "unknown" as const,
        message: "TWAP start failed.",
        retryable: false,
      };
      setTwapError(shape);
    }
  };

  const rankedLegs = createMemo(() => {
    const state = rfq.state();
    if (state.kind !== "ready" && state.kind !== "stale") return [] as RfqLegView[];
    return state.value.legs.slice().sort((a, b) => (b.netOutput ?? -Infinity) - (a.netOutput ?? -Infinity));
  });

  return (
    <div class="panel-stack">
      <Panel
        title="Adaptive TWAP"
        subtitle="Chunk, execute, observe liquidity recovery, recalculate; fixed cron is fallback only"
        badge={<Badge tone={twapDenial() ? "warning" : "positive"}>{twapDenial() ? "UNAVAILABLE" : "READY"}</Badge>}
      >
        <form
          class="ticket"
          onSubmit={(event) => {
            event.preventDefault();
            void startTwap();
          }}
        >
          <div class="ticket__grid">
            <label class="field">
              <span class="field__label">Total amount (USD)</span>
              <input
                class="input"
                inputmode="decimal"
                aria-label="TWAP total amount"
                value={amount()}
                onInput={(event) => setAmount(event.currentTarget.value)}
              />
            </label>
            <label class="field">
              <span class="field__label">Max slippage (bps, hard cap)</span>
              <input
                class="input"
                inputmode="numeric"
                aria-label="TWAP max slippage bps"
                value={slippage()}
                onInput={(event) => setSlippage(event.currentTarget.value)}
              />
            </label>
            <label class="field">
              <span class="field__label">Max price impact (bps)</span>
              <input
                class="input"
                inputmode="numeric"
                aria-label="TWAP max price impact bps"
                value={impact()}
                onInput={(event) => setImpact(event.currentTarget.value)}
              />
            </label>
            <label class="field">
              <span class="field__label">Interval (ms)</span>
              <input
                class="input"
                inputmode="numeric"
                aria-label="TWAP interval ms"
                value={interval()}
                onInput={(event) => setInterval(event.currentTarget.value)}
              />
            </label>
            <label class="field">
              <span class="field__label">Max chunks</span>
              <input
                class="input"
                inputmode="numeric"
                aria-label="TWAP max chunks"
                value={maxChunks()}
                onInput={(event) => setMaxChunks(event.currentTarget.value)}
              />
            </label>
          </div>
          <ActionButton type="submit" tone="primary" disabled={!twapValid() || twapDenial() !== null}>
            Start adaptive TWAP
          </ActionButton>
          <DenialNote denial={twapDenial()} />
        </form>

        <Show
          when={twapState()}
          fallback={
            <AsyncSurface<ExecutionProgress>
              state={progress.state()}
              nowMs={ws.nowMs()}
              onRetry={() => void progress.run()}
              emptyTitle="No adaptive execution running"
              emptyDetail="Start a TWAP or load current progress from the backend."
            >
              {(value) => <MetricGrid>{progressMetrics(value).map((m) => <Metric label={m.label} value={m.value} />)}</MetricGrid>}
            </AsyncSurface>
          }
        >
          {(value) => (
            <div class="panel-stack">
              <MetricGrid>{progressMetrics(value()).map((m) => <Metric label={m.label} value={m.value} />)}</MetricGrid>
              <Show when={value().haltReason}>
                <ReasonNote tone="danger">Halted: {value().haltReason}</ReasonNote>
              </Show>
              <Show when={value().state === "unknown"}>
                <ReasonNote tone="warning">
                  Execution state is unknown — reconcile before any further action. No blind retry.
                </ReasonNote>
              </Show>
            </div>
          )}
        </Show>
      </Panel>

      <Panel
        title="RFQ / solver competition"
        subtitle="Best-execution ranking across competing legs"
        badge={<Badge tone={rfqDenial() ? "warning" : "positive"}>{rfqDenial() ? "UNAVAILABLE" : "READY"}</Badge>}
      >
        <ActionButton disabled={rfqDenial() !== null} onClick={() => void rfq.run({})}>
          Request quotes
        </ActionButton>
        <DenialNote denial={rfqDenial()} />
        <AsyncSurface<RfqView>
          state={rfq.state()}
          nowMs={ws.nowMs()}
          onRetry={() => void rfq.run({})}
          emptyTitle="No RFQ in flight"
          emptyDetail="Submit a request to compare solver legs by simulated net output."
        >
          {(value) =>
            value.legs.length === 0 ? (
              <EmptyBlock title="No solver legs returned" />
            ) : (
              <ul class="route-list">
                {rankedLegs().map((leg) => (
                  <li class="route-list__item" data-solver={leg.solver}>
                    <Badge tone={leg.solver === value.bestSolver ? "positive" : leg.viable ? "muted" : "danger"}>
                      {leg.solver === value.bestSolver ? "BEST" : leg.viable ? "VIABLE" : "REJECTED"}
                    </Badge>
                    <span class="route-list__venue">{leg.solver}</span>
                    <span class="muted">out {formatAmount(leg.netOutput ?? Number(leg.amountOut))}</span>
                    <span class="route-list__share">{leg.latencyMs === null ? "—" : `${leg.latencyMs}ms`}</span>
                  </li>
                ))}
              </ul>
            )
          }
        </AsyncSurface>
      </Panel>
    </div>
  );
};

export default ExecutionPanel;
