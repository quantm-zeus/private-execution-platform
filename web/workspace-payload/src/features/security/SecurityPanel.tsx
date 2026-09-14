import { Show, createMemo, createSignal, type Component } from "solid-js";
import { formatUsd } from "../../core/format";
import type { WithdrawalReview } from "../../contracts/execution";
import { idleState, type DataState, type WorkspaceErrorShape } from "../../core/types";
import { useWorkspace } from "../../state/session";
import { ActionButton, Badge, KeyValue, Metric, MetricGrid, Panel, ReasonNote } from "../../components/ui/primitives";
import { DenialNote, ErrorBlock } from "../../components/ui/states";

const CONFIRM_PHRASE = "CONFIRM WITHDRAWAL";

/**
 * Web-only withdrawal surface with strong confirmation. It exposes no generic
 * signing or transfer capability: the backend receives a structured intent and
 * performs its own step-up authentication.
 */
export const SecurityPanel: Component = () => {
  const ws = useWorkspace();
  const [destination, setDestination] = createSignal("");
  const [amount, setAmount] = createSignal("");
  const [phrase, setPhrase] = createSignal("");
  const [review, setReview] = createSignal<WithdrawalReview | null>(null);
  const [submitState, setSubmitState] = createSignal<DataState<{ request_id: string }>>(idleState());

  const enabledChains = () => ws.session()?.chains.filter((chain) => chain.enabled) ?? [];
  const chain = () => enabledChains()[0]?.id ?? "base";
  const denial = createMemo(() => ws.mutationDenial("withdraw"));

  const amountValue = () => {
    const value = Number(amount().trim());
    return Number.isFinite(value) && value > 0 ? value : null;
  };
  const addressValid = () => destination().trim().length >= 8;
  const formValid = () => addressValid() && amountValue() !== null;

  const buildReview = () => {
    if (!formValid()) return;
    setReview({
      chain: chain(),
      token: "native",
      amount: amount().trim(),
      destination: destination().trim(),
      feeUsd: null,
      requiresStepUp: true,
    });
  };

  const submit = async () => {
    const current = review();
    if (!current) return;
    if (phrase() !== CONFIRM_PHRASE) return;
    if (denial() !== null) return;
    setSubmitState({ kind: "loading", sinceMs: ws.nowMs() });
    try {
      const result = await ws.command.send<{ request_id: string }>(
        "request_withdrawal",
        {
          chain: current.chain,
          token: current.token,
          amount: current.amount,
          destination: current.destination,
          confirmation: CONFIRM_PHRASE,
        },
        { idempotencyKey: `withdraw-${current.chain}-${current.destination}-${current.amount}` },
      );
      setSubmitState({
        kind: "ready",
        value: result,
        freshness: { receivedAtMs: ws.nowMs(), slot: null, sourceAgeMs: 0, ttlMs: 60_000 },
      });
      setReview(null);
      setPhrase("");
    } catch (error) {
      const shape = (error as { toShape?: () => WorkspaceErrorShape }).toShape?.() ?? {
        code: "unknown" as const,
        message: "Withdrawal request failed.",
        retryable: false,
      };
      setSubmitState({ kind: "error", error: shape });
    }
  };

  return (
    <div class="panel-stack">
      <Panel
        title="Session & security"
        subtitle="Memory-only session; lock destroys keys, worker, streams and private state"
        badge={<Badge tone={ws.killSwitch().enabled ? "danger" : "positive"}>
          {ws.killSwitch().enabled ? "KILL SWITCH" : "CLEAR"}
        </Badge>}
      >
        <MetricGrid>
          <Metric label="Protocol" value={ws.session()?.protocolVersion ?? "—"} />
          <Metric label="Session key id" value={ws.session()?.keyId ?? "—"} />
          <Metric
            label="Trading gate"
            value={ws.tradingEnabled() ? "ENABLED" : "DISABLED"}
            tone={ws.tradingEnabled() ? "positive" : "danger"}
          />
          <Metric label="Worker" value={ws.connection().phase} />
        </MetricGrid>
        <KeyValue
          rows={[
            {
              key: "kill",
              label: "Kill switch",
              value: ws.killSwitch().enabled ? (ws.killSwitch().reason ?? "engaged") : "clear",
              tone: ws.killSwitch().enabled ? "danger" : "positive",
            },
          ]}
        />
        <ReasonNote tone="info">
          No private key material is ever stored by this workspace; signing stays behind the backend Privy
          boundary. This application exposes no generic signing, message-signing or transfer surface.
        </ReasonNote>
      </Panel>

      <Panel
        title="Withdrawal"
        subtitle="Web-only, strong confirmation with explicit recipient and amount review"
        badge={<Badge tone={denial() ? "warning" : "positive"}>{denial() ? "DISABLED" : "AVAILABLE"}</Badge>}
      >
        <Show
          when={review()}
          fallback={
            <form
              class="ticket"
              onSubmit={(event) => {
                event.preventDefault();
                buildReview();
              }}
            >
              <div class="ticket__grid">
                <label class="field">
                  <span class="field__label">Destination address</span>
                  <input
                    class="input"
                    aria-label="Destination address"
                    autocomplete="off"
                    value={destination()}
                    onInput={(event) => setDestination(event.currentTarget.value)}
                  />
                </label>
                <label class="field">
                  <span class="field__label">Amount</span>
                  <input
                    class="input"
                    inputmode="decimal"
                    aria-label="Withdrawal amount"
                    value={amount()}
                    onInput={(event) => setAmount(event.currentTarget.value)}
                  />
                </label>
                <label class="field">
                  <span class="field__label">Chain</span>
                  <span class="input" aria-label="Withdrawal chain">
                    {chain()}
                  </span>
                </label>
              </div>
              <ActionButton type="submit" disabled={!formValid() || denial() !== null}>
                Review withdrawal
              </ActionButton>
              <DenialNote denial={denial()} />
              <ReasonNote tone="info">
                Treasury remains outside automated execution. Withdrawal requires step-up authentication on the
                backend and is never available through MCP or Telegram.
              </ReasonNote>
            </form>
          }
        >
          {(current) => (
            <div class="panel-stack">
              <KeyValue
                rows={[
                  { key: "dest", label: "Destination", value: current().destination },
                  { key: "amount", label: "Amount", value: `${current().amount} ${current().token}` },
                  { key: "chain", label: "Chain", value: current().chain },
                  { key: "fee", label: "Network fee", value: formatUsd(current().feeUsd) },
                ]}
              />
              <ReasonNote tone="danger">
                Confirm the destination carefully. On-chain transfers cannot be reversed.
              </ReasonNote>
              <label class="field">
                <span class="field__label">Type {CONFIRM_PHRASE} to authorize</span>
                <input
                  class="input"
                  aria-label="Withdrawal confirmation phrase"
                  autocomplete="off"
                  value={phrase()}
                  onInput={(event) => setPhrase(event.currentTarget.value)}
                />
              </label>
              <div class="ticket__actions">
                <ActionButton
                  tone="danger"
                  disabled={phrase() !== CONFIRM_PHRASE || denial() !== null}
                  onClick={() => void submit()}
                >
                  Request withdrawal
                </ActionButton>
                <ActionButton
                  onClick={() => {
                    setReview(null);
                    setPhrase("");
                  }}
                >
                  Cancel
                </ActionButton>
              </div>
              <DenialNote denial={denial()} />
            </div>
          )}
        </Show>
        <Show when={submitState().kind === "error"}>
          <ErrorBlock error={(submitState() as { error: WorkspaceErrorShape }).error} />
        </Show>
        <Show when={submitState().kind === "ready"}>
          <ReasonNote tone="info">
            Withdrawal request {(submitState() as { value: { request_id: string } }).value.request_id} submitted for
            backend step-up confirmation.
          </ReasonNote>
        </Show>
      </Panel>
    </div>
  );
};

export default SecurityPanel;
