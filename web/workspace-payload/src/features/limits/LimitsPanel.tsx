import {
  For,
  Show,
  createEffect,
  createMemo,
  createSignal,
  type JSX,
} from "solid-js";
import { toWorkspaceErrorShape, workspaceError } from "../../core/errors";
import { formatAge, formatBps, formatClock, formatUsd, truncateAddress } from "../../core/format";
import type {
  AmountType,
  LimitOrderView,
  OrderState,
  TradeSide,
} from "../../contracts/execution";
import { parseOrdersResponse } from "../../contracts/execution";
import { createCommandResource } from "../../state/command-state";
import { createSubmissionKeyTracker, isIndeterminateOutcome } from "../../core/idempotency";
import { useWorkspace } from "../../state/session";
import {
  ActionButton,
  Badge,
  Field,
  KeyValue,
  Panel,
  ReasonNote,
  type Tone,
} from "../../components/ui/primitives";
import {
  AsyncSurface,
  DenialNote,
  UnavailableBlock,
} from "../../components/ui/states";

/** Durable order lifecycle states and the tone each one is rendered with. */
const STATE_TONES: Record<OrderState, Tone> = {
  CREATED: "info",
  ACTIVE: "positive",
  TRIGGER_CANDIDATE: "warning",
  QUOTING: "info",
  SIMULATING: "info",
  EXECUTING: "warning",
  PARTIALLY_FILLED: "warning",
  FILLED: "positive",
  CANCELLED: "muted",
  EXPIRED: "muted",
  FAILED_RETRYABLE: "danger",
  FAILED_FINAL: "danger",
  UNKNOWN: "danger",
};

const AMOUNT_TYPES: readonly { readonly value: AmountType; readonly label: string }[] = [
  { value: "usd", label: "USD" },
  { value: "stablecoin", label: "Stablecoin" },
  { value: "token", label: "Token" },
];

interface OrdersResponse {
  readonly orders: readonly LimitOrderView[];
}

interface PlaceLimitPayload {
  readonly chain: string | null;
  readonly token_in: string | null;
  readonly token_out: string | null;
  readonly side: TradeSide;
  readonly order_type: "limit";
  readonly limit_price: number | null;
  readonly amount: number | null;
  readonly amount_type: AmountType;
  readonly max_buy_tax_bps: number | null;
  readonly max_sell_tax_bps: number | null;
  readonly max_price_impact_bps: number | null;
  readonly max_slippage_bps: number | null;
  readonly max_total_cost_usd: number | null;
  readonly allow_partial_fill: boolean;
  readonly expiry_ms: number | null;
}

function numberOrNull(raw: string): number | null {
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) ? parsed : null;
}

function expiryToMs(raw: string): number | null {
  if (raw === "") return null;
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Treat a missing, empty or whitespace-only token reference as absent so it
 * cannot slip past a `=== null` fail-closed gate and reach the backend.
 */
function nonBlank(value: string | null | undefined): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

/** Client-side validation: never send a structurally invalid intent. */
function validatePayload(payload: PlaceLimitPayload): string | null {
  // Fail closed on an incomplete target: a limit order with no chain/tokens is
  // not a tradeable intent and must never reach the backend.
  if (payload.chain === null || payload.token_in === null || payload.token_out === null) {
    return "Select a token in Discover to set the limit-order target.";
  }
  if (payload.amount === null || payload.amount <= 0) return "Enter a positive amount.";
  if (payload.limit_price === null || payload.limit_price <= 0) {
    return "Enter a positive limit net price.";
  }
  const caps: readonly (readonly [string, number | null])[] = [
    ["max buy tax", payload.max_buy_tax_bps],
    ["max sell tax", payload.max_sell_tax_bps],
    ["max price impact", payload.max_price_impact_bps],
    ["max slippage", payload.max_slippage_bps],
    ["max total cost", payload.max_total_cost_usd],
  ];
  for (const [label, value] of caps) {
    if (value !== null && (!Number.isFinite(value) || value < 0)) {
      return `Enter a non-negative ${label}.`;
    }
  }
  return null;
}

/**
 * Net-price limit order surface.
 *
 * The form only ever submits a structured intent; the durable order list is the
 * authoritative lifecycle. Unknown states are never retried blindly: the
 * operator must reconcile first.
 */
export default function LimitsPanel(): JSX.Element {
  const ws = useWorkspace();
  const command = ws.command;

  const orders = createCommandResource<OrdersResponse>(command, "get_orders", {
    capability: "limits",
    clock: () => ws.nowMs(),
    // Reject an unrenderable success document as a typed error instead of
    // marking it `ready` and throwing inside the order list (F2).
    validate: parseOrdersResponse,
  });
  const readDenial = createMemo(() => ws.capabilityDenial("limits"));
  const mutationDenial = createMemo(() => ws.mutationDenial("limits"));
  const submissionKeys = createSubmissionKeyTracker("limit");

  const [side, setSide] = createSignal<TradeSide>("buy");
  const [limitPrice, setLimitPrice] = createSignal("");
  const [amount, setAmount] = createSignal("");
  const [amountType, setAmountType] = createSignal<AmountType>("usd");
  const [maxBuyTaxBps, setMaxBuyTaxBps] = createSignal("");
  const [maxSellTaxBps, setMaxSellTaxBps] = createSignal("");
  const [maxPriceImpactBps, setMaxPriceImpactBps] = createSignal("");
  const [maxSlippageBps, setMaxSlippageBps] = createSignal("");
  const [maxTotalCostUsd, setMaxTotalCostUsd] = createSignal("");
  const [expiry, setExpiry] = createSignal("");
  const [allowPartial, setAllowPartial] = createSignal(true);

  const selected = () => ws.selectedInstrument();
  const chain = (): string | null =>
    selected()?.chain ?? ws.session()?.chains.find((c) => c.enabled)?.id ?? null;
  const chainInfo = createMemo(() => {
    const id = chain();
    if (id === null) return undefined;
    return ws.session()?.chains.find((c) => c.id === id && c.enabled);
  });
  /**
   * Resolve the pair from the shared Discover selection and the chain's
   * advertised quote/native token (BR-11), same as the market ticket. A missing
   * leg stays `null` so placement fails closed.
   */
  const resolvedTokens = createMemo(() =>
    side() === "buy"
      ? { tokenIn: nonBlank(chainInfo()?.nativeToken), tokenOut: nonBlank(selected()?.address) }
      : { tokenIn: nonBlank(selected()?.address), tokenOut: nonBlank(chainInfo()?.nativeToken) },
  );
  const targetError = createMemo<string | null>(() => {
    const tokens = resolvedTokens();
    if (tokens.tokenIn !== null && tokens.tokenOut !== null) return null;
    if (selected() === null) {
      return "Select a token in Discover to set the limit-order target.";
    }
    if (chainInfo() === undefined || chainInfo()?.nativeToken === null) {
      return "The chain's quote token is not advertised by the backend — placing is disabled.";
    }
    return "Select a token in Discover before placing a limit order.";
  });

  const [placing, setPlacing] = createSignal(false);
  const [actionError, setActionError] = createSignal<string | null>(null);
  const [reconcilingId, setReconcilingId] = createSignal<string | null>(null);
  /** Two-step acknowledgement before releasing an UNKNOWN guard (BR-9). */
  const [discardArmed, setDiscardArmed] = createSignal(false);
  /**
   * An ambiguous `place_limit_order` outcome. Kept (with its idempotency key and
   * exact payload) so a retry dedupes and a *changed* form cannot create a second
   * order while the first may still be open.
   */
  const [placeUnknown, setPlaceUnknown] = createSignal<{
    reason: string;
    signature: string;
    payload: PlaceLimitPayload;
  } | null>(null);

  // Load once the authoritative session confirms the capability *and* the
  // encrypted command channel is installed. A one-shot `onMount` check can
  // observe the pre-bootstrap (all-false) capability set if the user navigates
  // here before `/v1/bootstrap` settles, and firing before the BR-5 handoff
  // installs the real client would map the fail-closed stub's
  // `capability_missing` to a permanent `unavailable` state.
  let requested = false;
  createEffect(() => {
    if (readDenial() === null && ws.commandReady() && !requested) {
      requested = true;
      void orders.run();
    }
  });

  const buildPayload = (): PlaceLimitPayload => {
    const tokens = resolvedTokens();
    return {
      chain: chain(),
      token_in: tokens.tokenIn,
      token_out: tokens.tokenOut,
      side: side(),
      order_type: "limit",
      limit_price: numberOrNull(limitPrice()),
      amount: numberOrNull(amount()),
      amount_type: amountType(),
      max_buy_tax_bps: numberOrNull(maxBuyTaxBps()),
      max_sell_tax_bps: numberOrNull(maxSellTaxBps()),
      max_price_impact_bps: numberOrNull(maxPriceImpactBps()),
      max_slippage_bps: numberOrNull(maxSlippageBps()),
      max_total_cost_usd: numberOrNull(maxTotalCostUsd()),
      allow_partial_fill: allowPartial(),
      expiry_ms: expiryToMs(expiry()),
    };
  };

  /**
   * A non-empty cap that does not parse must never be silently dropped to `null`
   * ("no cap"): that turns a typo into a fail-open user constraint. Empty stays
   * null (explicitly no cap); anything else must be a finite non-negative number.
   */
  const capError = createMemo<string | null>(() => {
    const caps: readonly (readonly [string, string])[] = [
      ["max buy tax", maxBuyTaxBps()],
      ["max sell tax", maxSellTaxBps()],
      ["max price impact", maxPriceImpactBps()],
      ["max slippage", maxSlippageBps()],
      ["max total cost", maxTotalCostUsd()],
    ];
    for (const [label, raw] of caps) {
      const trimmed = raw.trim();
      if (trimmed === "") continue;
      const parsed = Number(trimmed);
      if (!Number.isFinite(parsed) || parsed < 0) {
        return `Enter a non-negative ${label}, or leave it empty for no cap.`;
      }
    }
    return null;
  });

  const place = async (): Promise<void> => {
    if (mutationDenial()) return;
    // In-flight guard: a fast backend plus an implicit form submit must not race
    // a second logical submission (the disabled button is not enough on its own).
    if (placing()) return;
    const capInvalid = capError();
    if (capInvalid !== null) {
      // `capError` is rendered reactively next to the form; do not duplicate it
      // in `actionError` (the action must still fail closed here).
      return;
    }
    const targetInvalid = targetError();
    if (targetInvalid !== null) {
      // `targetError` is rendered reactively; fail closed without duplicating it.
      return;
    }
    const payload = buildPayload();
    const invalid = validatePayload(payload);
    if (invalid !== null) {
      setActionError(invalid);
      return;
    }
    const expiryRaw = expiry().trim();
    if (expiryRaw !== "") {
      const expiryMs = expiryToMs(expiry());
      if (expiryMs === null) {
        setActionError("Enter a valid expiry, or leave it empty for an open expiry.");
        return;
      }
      if (expiryMs <= ws.nowMs()) {
        setActionError("Expiry must be in the future.");
        return;
      }
    }
    const signature = JSON.stringify(payload);
    const unknown = placeUnknown();
    if (unknown !== null && unknown.signature !== signature) {
      setActionError(
        "An earlier limit order is still UNKNOWN — retry the same order or reconcile it before placing a different one.",
      );
      return;
    }
    await submitPlace(payload, signature);
  };

  /** Submit one logical limit order; the caller supplies the stable signature. */
  const submitPlace = async (payload: PlaceLimitPayload, signature: string): Promise<void> => {
    setPlacing(true);
    setActionError(null);
    try {
      const idempotencyKey = submissionKeys.keyFor(signature);
      const result = await command.send<{ order_id?: unknown }>("place_limit_order", payload, {
        idempotencyKey,
      });
      // A 2xx is not proof of a placed order: the response must identify the
      // created order. A malformed/empty success (e.g. `result: null`) means the
      // write may still have committed, so it must keep the UNKNOWN guard and the
      // idempotency key rather than release them as a success.
      const orderId = result?.order_id;
      if (typeof orderId !== "string" || orderId.length === 0) {
        throw workspaceError("protocol", "Limit order response was missing an order id.");
      }
      // A repeat of the same parameters after success is a new logical order.
      submissionKeys.clear();
      setPlaceUnknown(null);
      setDiscardArmed(false);
      await orders.run();
    } catch (error) {
      const shape = toWorkspaceErrorShape(error);
      // If an UNKNOWN from an earlier attempt of THIS logical order already
      // exists, a failure on the retry must not release the guard or rotate the
      // key: a gateway can reject (401/400) before the idempotency store is
      // consulted, so it proves nothing about whether the first attempt committed.
      if (placeUnknown() !== null || isIndeterminateOutcome(shape.code, shape.retryable)) {
        // Ambiguous: never render as a plain failure. Keep the key and bind the
        // exact payload so a retry dedupes and a changed form is refused.
        setPlaceUnknown({ reason: shape.message, signature, payload });
        setActionError(null);
      } else {
        // A determinate rejection on a first attempt definitely did not commit;
        // rotate the key so a corrected retry is a genuinely new order rather
        // than a replay of the backend's cached rejection.
        submissionKeys.clear();
        setPlaceUnknown(null);
        setActionError(shape.message);
      }
    } finally {
      setPlacing(false);
    }
  };

  const retryPlaceUnknown = async (): Promise<void> => {
    const unknown = placeUnknown();
    if (unknown === null) return;
    if (mutationDenial() || placing()) return;
    await submitPlace(unknown.payload, unknown.signature);
  };

  const discardPlaceUnknown = (): void => {
    // Honest: the user attests they reconciled against the order list; the
    // backend exposes no create-lookup op yet (see BR-9).
    setDiscardArmed(false);
    submissionKeys.clear();
    setPlaceUnknown(null);
  };

  const cancel = async (order: LimitOrderView): Promise<void> => {
    // Re-gate at action time: a stale render or a flipped kill switch must not
    // let a write through.
    const denial = mutationDenial();
    if (denial !== null) {
      setActionError(denial.reason);
      return;
    }
    setActionError(null);
    try {
      // Cancellation is naturally idempotent per order id.
      await command.send(
        "cancel_order",
        { order_id: order.orderId },
        { idempotencyKey: `cancel-${order.orderId}` },
      );
      await orders.run();
    } catch (error) {
      setActionError(toWorkspaceErrorShape(error).message);
    }
  };

  const reconcile = async (order: LimitOrderView): Promise<void> => {
    setReconcilingId(order.orderId);
    setActionError(null);
    try {
      await command.send("get_order", { order_id: order.orderId });
      await orders.run();
    } catch (error) {
      setActionError(toWorkspaceErrorShape(error).message);
    } finally {
      setReconcilingId(null);
    }
  };

  const renderOrder = (order: LimitOrderView): JSX.Element => {
    const denial = mutationDenial();
    return (
      <li class="order-card" data-state={order.state} data-order-id={order.orderId}>
        <header class="order-card__head">
          <code class="order-card__id">{truncateAddress(order.orderId, 8, 6)}</code>
          <Badge tone={STATE_TONES[order.state]}>{order.state}</Badge>
          <span class="muted">updated {formatAge(Math.max(0, ws.nowMs() - order.updatedAtMs))} ago</span>
          <ActionButton
            tone="ghost"
            disabled={denial !== null}
            title={denial?.reason}
            onClick={() => void cancel(order)}
          >
            Cancel
          </ActionButton>
        </header>

        <Show when={order.state === "UNKNOWN"}>
          <ReasonNote tone="warning">
            State is UNKNOWN. The workspace performs no blind retry; reconcile with the backend and wait
            for an authoritative state before retrying or cancelling.
          </ReasonNote>
          <ActionButton
            disabled={reconcilingId() === order.orderId}
            title="Re-read the authoritative order state"
            onClick={() => void reconcile(order)}
          >
            {reconcilingId() === order.orderId ? "Reconciling…" : "Reconcile"}
          </ActionButton>
        </Show>

        <Show when={order.state === "PARTIALLY_FILLED"}>
          <ReasonNote tone="info">
            Partial fill: filled {order.filledAmount}, remaining {order.remainingAmount}. The remainder
            stays active until it fills, is cancelled or expires.
          </ReasonNote>
        </Show>

        <div class="order-card__fill">
          <span data-testid="order-filled">Filled: {order.filledAmount}</span>
          <span data-testid="order-remaining">Remaining: {order.remainingAmount}</span>
        </div>

        <KeyValue
          rows={[
            { key: "side", label: "Side", value: order.intent.side.toUpperCase() },
            {
              key: "amount",
              label: "Amount",
              value: `${order.intent.amount} ${order.intent.amountType}`,
            },
            { key: "limit", label: "Limit net price", value: order.intent.limitPrice ?? "—" },
            {
              key: "expiry",
              label: "Expiry",
              value: order.intent.expiryMs === null ? "—" : formatClock(order.intent.expiryMs),
            },
            {
              key: "impact",
              label: "Max price impact",
              value: formatBps(order.intent.maxPriceImpactBps),
            },
            {
              key: "slippage",
              label: "Max slippage",
              value: formatBps(order.intent.maxSlippageBps),
            },
            {
              key: "cost",
              label: "Max total cost",
              value: formatUsd(order.intent.maxTotalCostUsd),
            },
          ]}
        />

        <Show when={order.failureReason}>
          {(reason) => <ReasonNote tone="danger">{reason()}</ReasonNote>}
        </Show>

        <Show
          when={order.fills.length > 0}
          fallback={<p class="muted">No fills yet.</p>}
        >
          <ul class="fill-list">
            <For each={order.fills}>
              {(fill) => (
                <li class="fill-list__row">
                  <code>{truncateAddress(fill.executionId, 6, 4)}</code>
                  <span>
                    {fill.amountIn} → {fill.amountOut}
                  </span>
                  <span class="muted">{formatClock(fill.atMs)}</span>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </li>
    );
  };

  return (
    <Panel
      title="Net-price limit orders"
      subtitle="A chart crossing is only a trigger candidate; a net executable limit still requires exact simulation"
      badge={
        <Badge tone={readDenial() ? "warning" : "positive"}>
          {readDenial() ? "NOT AVAILABLE" : "AVAILABLE"}
        </Badge>
      }
    >
      <Show
        when={readDenial()}
        fallback={
          <div class="panel-stack">
            <form
              class="ticket"
              onSubmit={(event) => {
                event.preventDefault();
                void place();
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
              </div>

              <p class="muted" data-testid="limit-target">
                Target:{" "}
                <Show when={selected()} fallback="No target selected">
                  {(instrument) => (
                    <>
                      <strong>{instrument().symbol}</strong>{" "}
                      <code>{truncateAddress(instrument().address, 6, 6)}</code> on{" "}
                      {instrument().chain}
                    </>
                  )}
                </Show>{" "}
                · pair {resolvedTokens().tokenIn ?? "—"} → {resolvedTokens().tokenOut ?? "—"}
              </p>

              <div class="ticket__grid">
                <Field label="Limit net price" forId="limit-net-price">
                  <input
                    id="limit-net-price"
                    class="input"
                    inputmode="decimal"
                    aria-label="Limit net price"
                    value={limitPrice()}
                    onInput={(event) => setLimitPrice(event.currentTarget.value)}
                  />
                </Field>

                <Field label="Amount" forId="limit-amount">
                  <input
                    id="limit-amount"
                    class="input"
                    inputmode="decimal"
                    aria-label="Limit amount"
                    value={amount()}
                    onInput={(event) => setAmount(event.currentTarget.value)}
                  />
                </Field>

                <Field label="Amount type" forId="limit-amount-type">
                  <select
                    id="limit-amount-type"
                    class="input"
                    aria-label="Amount type"
                    value={amountType()}
                    onChange={(event) => setAmountType(event.currentTarget.value as AmountType)}
                  >
                    <For each={AMOUNT_TYPES}>
                      {(option) => <option value={option.value}>{option.label}</option>}
                    </For>
                  </select>
                </Field>

                <Field label="Max buy tax (bps)" forId="limit-max-buy-tax">
                  <input
                    id="limit-max-buy-tax"
                    class="input"
                    inputmode="decimal"
                    aria-label="Max buy tax bps"
                    value={maxBuyTaxBps()}
                    onInput={(event) => setMaxBuyTaxBps(event.currentTarget.value)}
                  />
                </Field>

                <Field label="Max sell tax (bps)" forId="limit-max-sell-tax">
                  <input
                    id="limit-max-sell-tax"
                    class="input"
                    inputmode="decimal"
                    aria-label="Max sell tax bps"
                    value={maxSellTaxBps()}
                    onInput={(event) => setMaxSellTaxBps(event.currentTarget.value)}
                  />
                </Field>

                <Field label="Max price impact (bps)" forId="limit-max-impact">
                  <input
                    id="limit-max-impact"
                    class="input"
                    inputmode="decimal"
                    aria-label="Max price impact bps"
                    value={maxPriceImpactBps()}
                    onInput={(event) => setMaxPriceImpactBps(event.currentTarget.value)}
                  />
                </Field>

                <Field label="Max slippage (bps)" forId="limit-max-slippage">
                  <input
                    id="limit-max-slippage"
                    class="input"
                    inputmode="decimal"
                    aria-label="Max slippage bps"
                    value={maxSlippageBps()}
                    onInput={(event) => setMaxSlippageBps(event.currentTarget.value)}
                  />
                </Field>

                <Field label="Max total cost (USD)" forId="limit-max-cost">
                  <input
                    id="limit-max-cost"
                    class="input"
                    inputmode="decimal"
                    aria-label="Max total cost USD"
                    value={maxTotalCostUsd()}
                    onInput={(event) => setMaxTotalCostUsd(event.currentTarget.value)}
                  />
                </Field>

                <Field label="Expiry" forId="limit-expiry">
                  <input
                    id="limit-expiry"
                    class="input"
                    type="datetime-local"
                    aria-label="Expiry"
                    value={expiry()}
                    onInput={(event) => setExpiry(event.currentTarget.value)}
                  />
                </Field>
              </div>

              <label class="field checkbox">
                <input
                  type="checkbox"
                  aria-label="Allow partial fill"
                  checked={allowPartial()}
                  onChange={(event) => setAllowPartial(event.currentTarget.checked)}
                />
                <span>Allow partial fill (remainder stays active)</span>
              </label>

              <div class="ticket__actions">
                <ActionButton
                  type="submit"
                  tone="primary"
                  disabled={mutationDenial() !== null || placing() || capError() !== null || targetError() !== null}
                >
                  Place limit order
                </ActionButton>
              </div>

              <DenialNote denial={mutationDenial()} />
              <Show when={targetError()}>
                {(message) => <ReasonNote tone="warning">{message()}</ReasonNote>}
              </Show>
              <Show when={capError()}>
                {(message) => <ReasonNote tone="danger">{message()}</ReasonNote>}
              </Show>
              <Show when={actionError()}>
                {(message) => <ReasonNote tone="danger">{message()}</ReasonNote>}
              </Show>
              <Show when={placeUnknown()}>
                {(unknown) => (
                  <div class="state-block state-block--error" role="alert" data-testid="limit-unknown">
                    <p class="state-block__title">Limit order outcome unknown</p>
                    <p class="state-block__detail">
                      {unknown().reason} The request may still have reached the backend, so this
                      order may already be open. Placing a different order now could create a
                      second one. Retrying the same order is idempotent and cannot duplicate it.
                    </p>
                    <div class="ticket__actions">
                      <ActionButton
                        disabled={mutationDenial() !== null || placing()}
                        onClick={() => void retryPlaceUnknown()}
                      >
                        Retry same order (idempotent)
                      </ActionButton>
                    </div>
                    <label class="field field--checkbox">
                      <input
                        type="checkbox"
                        aria-label="I verified the earlier limit order out-of-band"
                        checked={discardArmed()}
                        onChange={(event) => setDiscardArmed(event.currentTarget.checked)}
                      />
                      <span class="field__label">
                        I verified in the authoritative order list that the earlier order was not
                        created.
                      </span>
                    </label>
                    <ActionButton
                      tone="ghost"
                      disabled={!discardArmed()}
                      onClick={discardPlaceUnknown}
                    >
                      Discard UNKNOWN and continue
                    </ActionButton>
                  </div>
                )}
              </Show>
            </form>

            <section class="orders" aria-label="Limit orders">
              <header class="orders__head">
                <h3>Orders</h3>
                <ActionButton onClick={() => void orders.run()}>Refresh</ActionButton>
              </header>

              <Show when={mutationDenial()}>
                {(denial) => (
                  <ReasonNote tone="warning">Order actions disabled: {denial().reason}</ReasonNote>
                )}
              </Show>

              <AsyncSurface
                state={orders.state()}
                denial={readDenial()}
                nowMs={ws.nowMs()}
                onRetry={() => void orders.run()}
                emptyTitle="No limit orders"
                emptyDetail="Place a net-price limit order to see its durable lifecycle here."
                isEmpty={(value) => value.orders.length === 0}
              >
                {(value) => (
                  <ul class="order-list">
                    <For each={value.orders}>{(order) => renderOrder(order)}</For>
                  </ul>
                )}
              </AsyncSurface>
            </section>
          </div>
        }
      >
        <UnavailableBlock
          denial={readDenial()}
          detail="Requires the durable limit engine: place_limit_order, get_orders, get_order and cancel_order."
        />
      </Show>
    </Panel>
  );
}
