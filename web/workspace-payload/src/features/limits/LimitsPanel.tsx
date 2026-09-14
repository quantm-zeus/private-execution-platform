import {
  For,
  Show,
  createMemo,
  createSignal,
  onMount,
  type JSX,
} from "solid-js";
import { toWorkspaceErrorShape } from "../../core/errors";
import { formatAge, formatBps, formatClock, formatUsd, truncateAddress } from "../../core/format";
import type {
  AmountType,
  LimitOrderView,
  OrderState,
  TradeSide,
} from "../../contracts/execution";
import { createCommandResource } from "../../state/command-state";
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
  });
  const readDenial = createMemo(() => ws.capabilityDenial("limits"));
  const mutationDenial = createMemo(() => ws.mutationDenial("limits"));

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

  const [placing, setPlacing] = createSignal(false);
  const [actionError, setActionError] = createSignal<string | null>(null);
  const [reconcilingId, setReconcilingId] = createSignal<string | null>(null);

  onMount(() => {
    if (!readDenial()) void orders.run();
  });

  const buildPayload = (): PlaceLimitPayload => ({
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
  });

  const place = async (): Promise<void> => {
    if (mutationDenial()) return;
    setPlacing(true);
    setActionError(null);
    try {
      await command.send("place_limit_order", buildPayload());
      await orders.run();
    } catch (error) {
      setActionError(toWorkspaceErrorShape(error).message);
    } finally {
      setPlacing(false);
    }
  };

  const cancel = async (order: LimitOrderView): Promise<void> => {
    setActionError(null);
    try {
      await command.send("cancel_order", { order_id: order.orderId });
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
                  disabled={mutationDenial() !== null || placing()}
                >
                  Place limit order
                </ActionButton>
              </div>

              <DenialNote denial={mutationDenial()} />
              <Show when={actionError()}>
                {(message) => <ReasonNote tone="danger">{message()}</ReasonNote>}
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
