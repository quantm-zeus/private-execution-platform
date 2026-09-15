import { Show, createEffect, createMemo, createSignal, type Component } from "solid-js";
import { formatAmount, formatBps, formatPercent } from "../../core/format";
import { workspaceError } from "../../core/errors";
import type { WorkspaceErrorShape } from "../../core/types";
import type { ExecutionProgress, RfqLegView, RfqView, TwapRequest } from "../../contracts/execution";
import { createCommandResource } from "../../state/command-state";
import { createSubmissionKeyTracker, isIndeterminateOutcome } from "../../core/idempotency";
import { useWorkspace } from "../../state/session";
import { ActionButton, Badge, Metric, MetricGrid, Panel, ReasonNote } from "../../components/ui/primitives";
import { AsyncSurface, DenialNote, EmptyBlock, ErrorBlock } from "../../components/ui/states";

function num(raw: string): number | null {
  const value = Number(raw.trim());
  return Number.isFinite(value) && value > 0 ? value : null;
}

/**
 * Treat a missing, empty or whitespace-only token reference as absent so it
 * cannot slip past a `=== null` fail-closed gate and reach the backend.
 */
function nonBlank(value: string | null | undefined): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function progressMetrics(progress: ExecutionProgress) {
  const done = progress.chunksDone;
  const total = progress.chunksTotal;
  return [
    { label: "State", value: progress.state.toUpperCase() },
    { label: "Chunks", value: total === null ? "—" : `${done ?? "—"}/${total}` },
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
    ttlMs: 5_000,
  });
  const rfq = createCommandResource<RfqView>(ws.command, "submit_rfq", {
    capability: "rfq",
    ttlMs: 10_000,
  });

  const twapDenial = createMemo(() => ws.mutationDenial("twap"));
  const rfqDenial = createMemo(() => ws.mutationDenial("rfq"));
  // `get_execution_progress` is an ungated owner-scoped reconciliation read
  // (BR-9): the server serves it even when `twap` is not advertised, so the
  // client must not hide it behind `twap` or an UNKNOWN execution could never
  // be reconciled. The read stays fail-closed server-side.
  const progressDenial = (): null => null;

  // Load the current execution progress immediately; the ungated reconcile read
  // is always safe to attempt and the surface treats a failure as an error.
  let progressRequested = false;
  createEffect(() => {
    if (progressDenial() === null && !progressRequested) {
      progressRequested = true;
      void progress.run();
    }
  });

  const twapKeys = createSubmissionKeyTracker("twap");
  const rfqKeys = createSubmissionKeyTracker("rfq");
  const [twapUnknown, setTwapUnknown] = createSignal<{
    reason: string;
    signature: string;
    request: TwapRequest;
  } | null>(null);
  /** Two-step acknowledgement before releasing a TWAP UNKNOWN guard (BR-9). */
  const [discardArmed, setDiscardArmed] = createSignal(false);
  /**
   * In-flight guards. A double-click (or Enter resubmit) must not run two
   * logical submissions; the second could clear/rotate the key of the first
   * while it is still unresolved and start a duplicate execution.
   */
  const [twapSubmitting, setTwapSubmitting] = createSignal(false);
  const [rfqSubmitting, setRfqSubmitting] = createSignal(false);
  /**
   * An RFQ whose outcome could not be confirmed. Kept (with its idempotency
   * key and exact request) so a retry dedupes and a *different* request cannot
   * start while the first may still have been accepted.
   */
  const [rfqUnknown, setRfqUnknown] = createSignal<{
    reason: string;
    signature: string;
  } | null>(null);
  /** Two-step acknowledgement before releasing an RFQ UNKNOWN guard (BR-9). */
  const [rfqDiscardArmed, setRfqDiscardArmed] = createSignal(false);

  const selected = () => ws.selectedInstrument();
  const chain = (): string | null =>
    selected()?.chain ?? ws.session()?.chains.find((c) => c.enabled)?.id ?? null;
  const chainInfo = createMemo(() => {
    const id = chain();
    if (id === null) return undefined;
    return ws.session()?.chains.find((c) => c.id === id && c.enabled);
  });
  /**
   * Resolve the buy pair (this surface has no sell toggle): the chain's
   * advertised quote/native token in (BR-11), the selected instrument out.
   */
  const resolvedTokens = createMemo(() => ({
    tokenIn: nonBlank(chainInfo()?.nativeToken),
    tokenOut: nonBlank(selected()?.address),
  }));
  const targetError = createMemo<string | null>(() => {
    if (chain() === null) {
      return "No enabled chain was advertised by the backend — execution is disabled.";
    }
    const tokens = resolvedTokens();
    if (tokens.tokenIn === null || tokens.tokenOut === null) {
      if (selected() === null) return "Select a token in Discover to set the execution target.";
      return "The chain's quote token is not advertised by the backend — execution is disabled.";
    }
    return null;
  });

  /** The exact RFQ request the surface submits (extended with the target instrument). */
  const rfqRequest = createMemo<Record<string, unknown>>(() => {
    const tokens = resolvedTokens();
    return { chain: chain(), token_in: tokens.tokenIn, token_out: tokens.tokenOut };
  });

  /** The exact TWAP request the form currently describes, or null if invalid. */
  const twapRequest = createMemo<TwapRequest | null>(() => {
    if (num(amount()) === null || num(slippage()) === null || num(impact()) === null) return null;
    // Never silently substitute a default for an invalid scheduling value: a
    // user who typed an unusable interval/max-chunks must see the form blocked.
    const intervalMs = num(interval());
    const chunks = num(maxChunks());
    if (intervalMs === null || chunks === null) return null;
    const chainId = chain();
    const tokens = resolvedTokens();
    if (chainId === null || tokens.tokenIn === null || tokens.tokenOut === null) return null;
    return {
      chain: chainId,
      tokenIn: tokens.tokenIn,
      tokenOut: tokens.tokenOut,
      side: "buy",
      totalAmount: amount(),
      amountType: "usd",
      maxSlippageBps: Math.round(num(slippage())!),
      maxPriceImpactBps: Math.round(num(impact())!),
      intervalMs: Math.round(intervalMs),
      maxChunks: Math.round(chunks),
    };
  });
  const twapValid = createMemo(() => twapRequest() !== null);
  const twapSignature = createMemo(() => {
    const request = twapRequest();
    return request === null ? null : JSON.stringify(request);
  });
  const twapBlockedByUnknown = createMemo(() => {
    const unknown = twapUnknown();
    const signature = twapSignature();
    return unknown !== null && signature !== null && unknown.signature !== signature;
  });

  const requestRfq = async (): Promise<void> => {
    // Re-gate at action time: the retry affordance is not enough, a stale render
    // or flipped kill switch must not let the write out.
    const denial = rfqDenial();
    if (denial !== null) return;
    if (rfqSubmitting()) return;
    // Fail closed on an incomplete target: never submit a chain-less/null-token RFQ.
    if (targetError() !== null) return;
    const request = rfqRequest();
    const signature = JSON.stringify(request);
    // While a previous RFQ is UNKNOWN, only the exact same request may be
    // retried (same key -> backend dedupe). A different request is refused so an
    // unresolved RFQ cannot be doubled by a changed form.
    const unknown = rfqUnknown();
    if (unknown !== null && unknown.signature !== signature) return;
    const hadUnknown = unknown !== null;
    const key = rfqKeys.keyFor(signature);
    setRfqSubmitting(true);
    try {
      await rfq.run(request, { idempotencyKey: key });
      const state = rfq.state();
      if (state.kind === "ready" || state.kind === "stale") {
        rfqKeys.clear();
        setRfqUnknown(null);
        setRfqDiscardArmed(false);
      } else if (state.kind === "unavailable") {
        // A retry of an existing UNKNOWN must not release the guard on a
        // determinate rejection: a gateway can reject before the idempotency
        // store is consulted.
        if (hadUnknown) {
          setRfqUnknown({ reason: state.reason, signature });
        } else {
          rfqKeys.clear();
          setRfqUnknown(null);
        }
      } else if (state.kind === "error") {
        if (hadUnknown || isIndeterminateOutcome(state.error.code, state.error.retryable)) {
          setRfqUnknown({ reason: state.error.message, signature });
        } else {
          // A determinate rejection of a first attempt: a corrected retry is a
          // genuinely new logical RFQ.
          rfqKeys.clear();
          setRfqUnknown(null);
          setRfqDiscardArmed(false);
        }
      }
    } finally {
      setRfqSubmitting(false);
    }
  };

  const discardRfqUnknown = (): void => {
    // Explicit two-step acknowledgement before a *different* RFQ may run.
    setRfqDiscardArmed(false);
    rfqKeys.clear();
    setRfqUnknown(null);
  };

  /** Submit one logical TWAP; the caller supplies the stable signature/key. */
  const submitTwap = async (request: TwapRequest, signature: string): Promise<void> => {
    // In-flight guard: a double-click must not clear the key of the first
    // attempt while it is still unresolved.
    if (twapSubmitting()) return;
    const idempotencyKey = twapKeys.keyFor(signature);
    // A retry of an already-UNKNOWN submission must never release the guard on a
    // determinate rejection: a gateway can reject before the idempotency store is
    // consulted, so it does not prove the first attempt did not start.
    const hadUnknown = twapUnknown() !== null;
    setTwapSubmitting(true);
    setTwapError(null);
    try {
      const result = await ws.command.send<ExecutionProgress>("start_twap", request, {
        idempotencyKey,
      });
      if (!result || typeof result.state !== "string") {
        throw workspaceError("protocol", "TWAP response was missing an execution state.");
      }
      twapKeys.clear();
      setTwapUnknown(null);
      setDiscardArmed(false);
      setTwapState(result);
    } catch (error) {
      const shape = (error as { toShape?: () => WorkspaceErrorShape }).toShape?.() ?? {
        code: "unknown" as const,
        message: "TWAP start failed.",
        retryable: false,
      };
      if (hadUnknown || isIndeterminateOutcome(shape.code, shape.retryable)) {
        // Never render an ambiguous outcome as a plain failure: the key is kept
        // and the request is bound so a retry dedupes.
        setTwapUnknown({ reason: shape.message, signature, request });
        setTwapError(null);
      } else {
        // Determinate rejection of a first attempt rotates the key; the next
        // attempt is new.
        twapKeys.clear();
        setTwapUnknown(null);
        setTwapError(shape);
      }
    } finally {
      setTwapSubmitting(false);
    }
  };

  const startTwap = async () => {
    // Re-gate at action time (the ErrorBlock retry path bypasses the button).
    const denial = twapDenial();
    if (denial !== null) {
      setTwapError({ code: "capability_missing", message: denial.reason, retryable: false });
      return;
    }
    // Fail closed on an incomplete target before ever building the request.
    const targetProblem = targetError();
    if (targetProblem !== null) {
      setTwapError({ code: "capability_missing", message: targetProblem, retryable: false });
      return;
    }
    const request = twapRequest();
    if (request === null) return;
    const signature = JSON.stringify(request);
    // While a previous submission is UNKNOWN, only the *same* request may be
    // retried (same key -> backend dedupe). A changed request is refused so a
    // still-in-flight TWAP cannot be doubled by an edited form.
    const unknown = twapUnknown();
    if (unknown !== null && unknown.signature !== signature) {
      setTwapError({
        code: "freshness",
        message:
          "An earlier TWAP submission is still UNKNOWN — retry the same request or reconcile it before starting a different one.",
        retryable: true,
      });
      return;
    }
    await submitTwap(request, signature);
  };

  /** Idempotent retry of the exact UNKNOWN request (same key). */
  const retryTwapUnknown = async () => {
    const unknown = twapUnknown();
    if (unknown === null) return;
    const denial = twapDenial();
    if (denial !== null) {
      setTwapError({ code: "capability_missing", message: denial.reason, retryable: false });
      return;
    }
    await submitTwap(unknown.request, unknown.signature);
  };

  const discardTwapUnknown = () => {
    // The user attests they reconciled the unknown against Orders/history; the
    // backend exposes no lookup op for it yet (see BR-9). This never claims the
    // original did not happen. Two-step: the acknowledgement is required first.
    setDiscardArmed(false);
    twapKeys.clear();
    setTwapUnknown(null);
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
          <ActionButton
            type="submit"
            tone="primary"
            disabled={!twapValid() || twapDenial() !== null || twapBlockedByUnknown() || twapSubmitting() || targetError() !== null}
          >
            Start adaptive TWAP
          </ActionButton>
          <DenialNote denial={twapDenial()} />
          <Show when={targetError()}>
            {(message) => <ReasonNote tone="warning">{message()}</ReasonNote>}
          </Show>
          <Show when={!twapValid() && amount().trim() !== ""}>
            <ReasonNote tone="warning">
              Enter positive amount, slippage, price impact, interval and max chunks.
            </ReasonNote>
          </Show>
        </form>

        <Show when={twapUnknown()}>
          {(unknown) => (
            <div class="panel-stack">
              <ReasonNote tone="warning">
                TWAP submission outcome UNKNOWN: {unknown().reason} The request may still have reached
                the backend. Retrying the same request is idempotent; starting a different TWAP is
                blocked until this is reconciled.
              </ReasonNote>
              <div class="actions">
                <ActionButton onClick={() => void retryTwapUnknown()} disabled={twapDenial() !== null || twapSubmitting()}>
                  Retry same request
                </ActionButton>
              </div>
              <label class="field field--checkbox">
                <input
                  type="checkbox"
                  aria-label="I verified the earlier TWAP out-of-band"
                  checked={discardArmed()}
                  onChange={(event) => setDiscardArmed(event.currentTarget.checked)}
                />
                <span class="field__label">
                  I verified in the authoritative order/execution list that the earlier TWAP was not
                  started.
                </span>
              </label>
              <ActionButton tone="danger" disabled={!discardArmed()} onClick={discardTwapUnknown}>
                Discard UNKNOWN and continue
              </ActionButton>
            </div>
          )}
        </Show>
        <Show when={twapBlockedByUnknown()}>
          <ReasonNote tone="danger">
            The form no longer matches the UNKNOWN TWAP submission — restore it to retry idempotently,
            or reconcile and discard the unknown first.
          </ReasonNote>
        </Show>

        <Show
          when={twapState()}
          fallback={
            <AsyncSurface<ExecutionProgress>
              state={progress.state()}
              denial={progressDenial()}
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
        <Show when={twapError()}>
          {(error) => <ErrorBlock error={error()} onRetry={() => void startTwap()} />}
        </Show>
      </Panel>

      <Panel
        title="RFQ / solver competition"
        subtitle="Best-execution ranking across competing legs"
        badge={<Badge tone={rfqDenial() ? "warning" : "positive"}>{rfqDenial() ? "UNAVAILABLE" : "READY"}</Badge>}
      >
        <ActionButton
          disabled={rfqDenial() !== null || rfqSubmitting() || rfqUnknown() !== null || targetError() !== null}
          onClick={() => void requestRfq()}
        >
          Request quotes
        </ActionButton>
        <DenialNote denial={rfqDenial()} />
        <Show when={targetError()}>
          {(message) => <ReasonNote tone="warning">{message()}</ReasonNote>}
        </Show>
        <Show when={rfqUnknown()}>
          {(unknown) => (
            <div class="panel-stack">
              <ReasonNote tone="warning">
                RFQ outcome UNKNOWN: {unknown().reason} The request may still have reached the
                backend. Retrying the same request is idempotent (same key); a different request is
                blocked until this is reconciled.
              </ReasonNote>
              <div class="actions">
                <ActionButton
                  onClick={() => void requestRfq()}
                  disabled={rfqDenial() !== null || rfqSubmitting()}
                >
                  Retry same request
                </ActionButton>
              </div>
              <label class="field field--checkbox">
                <input
                  type="checkbox"
                  aria-label="I verified the earlier RFQ out-of-band"
                  checked={rfqDiscardArmed()}
                  onChange={(event) => setRfqDiscardArmed(event.currentTarget.checked)}
                />
                <span class="field__label">
                  I verified in the authoritative execution list that the earlier RFQ was not started.
                </span>
              </label>
              <ActionButton tone="danger" disabled={!rfqDiscardArmed()} onClick={discardRfqUnknown}>
                Discard UNKNOWN and continue
              </ActionButton>
            </div>
          )}
        </Show>
        <AsyncSurface<RfqView>
          state={rfq.state()}
          nowMs={ws.nowMs()}
          onRetry={() => void requestRfq()}
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
                    <span class="muted">net out {formatAmount(leg.netOutput)}</span>
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
