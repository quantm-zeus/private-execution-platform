import { Show, createMemo, createSignal, type Component, type JSX } from "solid-js";
import { formatAmount, formatBps, formatPercent, formatUsd } from "../../core/format";
import type { AmountType, NetEconomics, OrderType, QuotePreview, TradeSide } from "../../contracts/execution";
import { createCommandResource } from "../../state/command-state";
import { useWorkspace } from "../../state/session";
import { isFresh, type DataState, type WorkspaceErrorShape } from "../../core/types";
import { ActionButton, Badge, KeyValue, Panel, ReasonNote } from "../../components/ui/primitives";
import {
  AsyncSurface,
  DenialNote,
  ErrorBlock,
  FreshnessBadge,
  StaleRibbon,
} from "../../components/ui/states";

export interface TradePanelProps {
  readonly chain?: string;
  readonly tokenIn?: string;
  readonly tokenOut?: string;
  readonly orderType?: OrderType;
}

function parseAmount(raw: string): number | null {
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  const value = Number(trimmed);
  if (!Number.isFinite(value) || value <= 0) return null;
  return value;
}

function parseBps(raw: string): number | null {
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  const value = Number(trimmed);
  if (!Number.isFinite(value) || value < 0) return null;
  return Math.round(value);
}

function economicsRows(economics: NetEconomics): { key: string; label: string; value: JSX.Element; tone?: "positive" | "warning" | "danger" }[] {
  return [
    { key: "gross", label: "Gross output (informational)", value: formatAmount(economics.grossOutput) },
    {
      key: "net",
      label: "Simulated net output (execution truth)",
      value: formatAmount(economics.netOutput),
      tone: "positive" as const,
    },
    { key: "tax", label: "Tax", value: formatBps(economics.taxBps) },
    { key: "dex", label: "DEX / provider fee", value: formatBps(economics.dexFeeBps) },
    { key: "gas", label: "Gas", value: formatUsd(economics.gasUsd) },
    { key: "impact", label: "Price impact", value: formatBps(economics.priceImpactBps) },
    { key: "slippage", label: "Expected slippage", value: formatBps(economics.expectedSlippageBps) },
    { key: "mev", label: "MEV risk", value: formatBps(economics.mevRiskBps) },
    {
      key: "failure",
      label: "Failure probability",
      value: formatPercent(economics.failureProbability),
    },
    { key: "min", label: "Minimum received", value: economics.minReceived ?? "—" },
  ];
}

export const TradePanel: Component<TradePanelProps> = (props) => {
  const ws = useWorkspace();
  const [side, setSide] = createSignal<TradeSide>("buy");
  const [amount, setAmount] = createSignal("");
  const [amountType, setAmountType] = createSignal<AmountType>("usd");
  const [slippage, setSlippage] = createSignal("100");
  const [impact, setImpact] = createSignal("150");
  const [maxCost, setMaxCost] = createSignal("");
  const [confirming, setConfirming] = createSignal(false);
  const [execState, setExecState] = createSignal<DataState<{ execution_id: string }>>({ kind: "idle" });
  const preview = createCommandResource<QuotePreview>(ws.command, "preview_market_order", {
    capability: "preview",
    ttlMs: 5_000,
  });

  const orderType = (): OrderType => props.orderType ?? "market";
  const parsedAmount = createMemo(() => parseAmount(amount()));
  const amountError = () =>
    amount().trim() !== "" && parsedAmount() === null ? "Enter a positive amount." : undefined;
  const chain = () => props.chain ?? ws.session()?.chains.find((c) => c.enabled)?.id ?? "base";

  const previewState = () => preview.state();
  const previewStale = createMemo(() => {
    const state = previewState();
    if (state.kind === "ready") return !isFresh({ ...state.freshness, slot: null }, ws.nowMs());
    return state.kind === "stale";
  });

  const runPreview = async () => {
    if (parsedAmount() === null) return;
    setConfirming(false);
    await preview.run({
      intent: {
        chain: chain(),
        token_in: props.tokenIn ?? null,
        token_out: props.tokenOut ?? null,
        side: side(),
        amount_type: amountType(),
        amount: amount(),
        order_type: orderType(),
        max_slippage_bps: parseBps(slippage()),
        max_price_impact_bps: parseBps(impact()),
        max_total_cost_usd: parseAmount(maxCost()),
      },
    });
  };

  const executeDenial = createMemo(() => ws.mutationDenial("execute"));

  /**
   * A preview is only executable when the backend did not request explicit
   * revalidation, it has not expired, and its local TTL is still fresh.
   */
  const previewUsable = createMemo(() => {
    const state = previewState();
    if (state.kind !== "ready") return false;
    if (state.value.revalidationRequired) return false;
    if (state.value.expiresAtMs !== null && ws.nowMs() >= state.value.expiresAtMs) return false;
    return !previewStale();
  });

  const previewBlockReason = createMemo(() => {
    const state = previewState();
    if (state.kind !== "ready") return null;
    if (state.value.revalidationRequired) return "Backend requires revalidation before executing — preview again.";
    if (state.value.expiresAtMs !== null && ws.nowMs() >= state.value.expiresAtMs) {
      return "Preview expired — preview again.";
    }
    if (previewStale()) return "Preview is stale — preview again.";
    return null;
  });

  const canExecute = createMemo(() => executeDenial() === null && previewUsable() && !confirming());

  const confirmExecute = async () => {
    const state = previewState();
    // Re-gate at confirm time: capability, kill switch, expiry and freshness can
    // all change while the confirmation panel is open.
    if (state.kind !== "ready" || !previewUsable()) {
      setConfirming(false);
      setExecState({
        kind: "error",
        error: {
          code: "freshness",
          message: previewBlockReason() ?? "Preview is no longer executable.",
          retryable: true,
        },
      });
      return;
    }
    const denial = executeDenial();
    if (denial !== null) {
      setConfirming(false);
      setExecState({
        kind: "error",
        error: { code: "capability_missing", message: denial.reason, retryable: false },
      });
      return;
    }
    setConfirming(false);
    setExecState({ kind: "loading", sinceMs: ws.nowMs() });
    try {
      const result = await ws.command.send<{ execution_id: string }>(
        "execute_market_order",
        { quote_id: state.value.quoteId, idempotency_key: state.value.quoteId },
        {},
      );
      setExecState({
        kind: "ready",
        value: result,
        freshness: { receivedAtMs: ws.nowMs(), slot: null, sourceAgeMs: 0, ttlMs: 30_000 },
      });
    } catch (error) {
      const shape = (error as { toShape?: () => WorkspaceErrorShape }).toShape?.() ?? {
        code: "unknown" as const,
        message: "Execution failed.",
        retryable: false,
      };
      setExecState({ kind: "error", error: shape });
    }
  };

  return (
    <div class="panel-stack">
      <Panel
        title="Market ticket"
        subtitle="Exact simulated NET delta is execution truth; the raw quote is informational"
      >
        <form
          class="ticket"
          onSubmit={(event) => {
            event.preventDefault();
            void runPreview();
          }}
        >
          <div class="ticket__side" role="group" aria-label="Side">
            <button
              type="button"
              class="chip-button"
              aria-pressed={side() === "buy"}
              onClick={() => setSide("buy")}
            >
              Buy
            </button>
            <button
              type="button"
              class="chip-button"
              aria-pressed={side() === "sell"}
              onClick={() => setSide("sell")}
            >
              Sell
            </button>
            <Badge tone="muted">chain: {chain()}</Badge>
          </div>
          <div class="ticket__grid">
            <label class="field">
              <span class="field__label">Amount</span>
              <input
                class="input"
                inputmode="decimal"
                aria-label="Amount"
                value={amount()}
                onInput={(event) => setAmount(event.currentTarget.value)}
              />
              {amountError() ? (
                <span class="field__error" role="alert">
                  {amountError()}
                </span>
              ) : null}
            </label>
            <label class="field">
              <span class="field__label">Amount unit</span>
              <select
                class="input"
                aria-label="Amount unit"
                value={amountType()}
                onChange={(event) => setAmountType(event.currentTarget.value as AmountType)}
              >
                <option value="usd">USD</option>
                <option value="stablecoin">Stablecoin</option>
                <option value="token">Token quantity</option>
              </select>
            </label>
            <label class="field">
              <span class="field__label">Max slippage (bps)</span>
              <input
                class="input"
                inputmode="numeric"
                aria-label="Max slippage bps"
                value={slippage()}
                onInput={(event) => setSlippage(event.currentTarget.value)}
              />
            </label>
            <label class="field">
              <span class="field__label">Max price impact (bps)</span>
              <input
                class="input"
                inputmode="numeric"
                aria-label="Max price impact bps"
                value={impact()}
                onInput={(event) => setImpact(event.currentTarget.value)}
              />
            </label>
            <label class="field">
              <span class="field__label">Max total cost (USD, optional)</span>
              <input
                class="input"
                inputmode="decimal"
                aria-label="Max total cost usd"
                value={maxCost()}
                onInput={(event) => setMaxCost(event.currentTarget.value)}
              />
            </label>
          </div>
          <div class="ticket__actions">
            <ActionButton type="submit" disabled={parsedAmount() === null}>
              Preview
            </ActionButton>
          </div>
        </form>
      </Panel>

      <Panel
        title="Net economics & route"
        subtitle="Every cost is part of the route score"
        badge={
          <Show when={previewState().kind === "ready" || previewState().kind === "stale"}>
            <FreshnessBadge
              freshness={(previewState() as { freshness: { receivedAtMs: number; sourceAgeMs: number; ttlMs: number } }).freshness}
              nowMs={ws.nowMs()}
            />
          </Show>
        }
      >
        <AsyncSurface<QuotePreview>
          state={previewState()}
          nowMs={ws.nowMs()}
          onRetry={() => void runPreview()}
          emptyTitle="No preview yet"
          emptyDetail="Enter an amount and preview to see exact net economics."
        >
          {(quote, stale) => (
            <div class="panel-stack">
              <Show when={stale}>
                <StaleRibbon
                  ageMs={quote.sourceAgeMs}
                  reason="Preview exceeds its freshness TTL — re-preview before executing."
                />
              </Show>
              <KeyValue rows={economicsRows(quote.economics)} />
              <div>
                <h3 class="section-title">Route</h3>
                {quote.route.length === 0 ? (
                  <p class="muted">No route legs reported.</p>
                ) : (
                  <ul class="route-list">
                    {quote.route.map((leg) => (
                      <li class="route-list__item" data-route-index={leg.index}>
                        <Badge tone={leg.kind === "split" ? "info" : "muted"}>{leg.kind}</Badge>
                        <span class="route-list__venue">{leg.venue}</span>
                        <span class="muted">
                          {leg.tokenIn} → {leg.tokenOut}
                        </span>
                        <span class="route-list__share">{formatPercent(leg.sharePct / 100)}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <p class="muted">
                slot {quote.slot ?? "—"} · source age {quote.sourceAgeMs}ms · revalidation{" "}
                {quote.revalidationRequired ? "required" : "not required"}
              </p>
            </div>
          )}
        </AsyncSurface>
      </Panel>

      <Panel title="Execute" subtitle="Fails closed unless capability, trading gate and freshness agree">
        <Show
          when={!confirming()}
          fallback={
            <div class="panel-stack">
              <ReasonNote tone="danger">
                Confirm market {side()} for {amount()} {amountType()} on {chain()}. Execution cannot be undone.
              </ReasonNote>
              <Show when={previewBlockReason()}>
                <ReasonNote tone="warning">{previewBlockReason()}</ReasonNote>
              </Show>
              <div class="ticket__actions">
                <ActionButton
                  tone="danger"
                  disabled={executeDenial() !== null || !previewUsable()}
                  onClick={() => void confirmExecute()}
                >
                  Confirm execution
                </ActionButton>
                <ActionButton onClick={() => setConfirming(false)}>Cancel</ActionButton>
              </div>
              <DenialNote denial={executeDenial()} />
            </div>
          }
        >
          <ActionButton
            tone="primary"
            disabled={!canExecute()}
            onClick={() => setConfirming(true)}
          >
            Execute {side()}
          </ActionButton>
        </Show>
        <DenialNote denial={executeDenial()} />
        <Show when={previewStale() && executeDenial() === null}>
          <ReasonNote tone="warning">Preview is stale — re-preview before executing.</ReasonNote>
        </Show>
        <Show when={execState().kind === "error"}>
          <ErrorBlock error={(execState() as { error: WorkspaceErrorShape }).error} />
        </Show>
        <Show when={execState().kind === "ready"}>
          <ReasonNote tone="info">
            Submitted execution {(execState() as { value: { execution_id: string } }).value.execution_id}. Track it in
            the Execution view.
          </ReasonNote>
        </Show>
        <ReasonNote tone="info">
          Preview stays available while trading is disabled. This surface has no generic signing or transfer control.
        </ReasonNote>
      </Panel>
    </div>
  );
};

export default TradePanel;
