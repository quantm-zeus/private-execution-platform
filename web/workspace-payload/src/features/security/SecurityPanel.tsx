import { Show, createMemo, createSignal, type Component } from "solid-js";
import { formatUsd } from "../../core/format";
import { workspaceError } from "../../core/errors";
import type { WithdrawalReview } from "../../contracts/execution";
import { idleState, type DataState, type WorkspaceErrorShape } from "../../core/types";
import { newIdempotencyKey, isIndeterminateOutcome } from "../../core/idempotency";
import { useWorkspace } from "../../state/session";
import { ActionButton, Badge, KeyValue, Metric, MetricGrid, Panel, ReasonNote } from "../../components/ui/primitives";
import { DenialNote, ErrorBlock } from "../../components/ui/states";
import WalletLimitsPanel from "./WalletLimitsPanel";

const CONFIRM_PHRASE = "CONFIRM WITHDRAWAL";

function sameReview(a: WithdrawalReview, b: WithdrawalReview): boolean {
  return (
    a.chain === b.chain &&
    a.token === b.token &&
    a.amount === b.amount &&
    a.destination === b.destination
  );
}

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
  // One key per reviewed withdrawal so a failed/retried submit is idempotent.
  // It survives a cancel/re-review of an *unconfirmed* (UNKNOWN) submission so
  // an already-accepted withdrawal cannot be duplicated; a determinate
  // rejection clears it so a corrected re-review is a distinct authorization.
  const [reviewKey, setReviewKey] = createSignal<string | null>(null);
  /** The exact reviewed withdrawal that produced an UNKNOWN outcome, if any. */
  const [unknownReview, setUnknownReview] = createSignal<WithdrawalReview | null>(null);
  const [submitState, setSubmitState] = createSignal<DataState<{ request_id: string }>>(idleState());
  /**
   * In-flight guard. A withdrawal is irreversible: a double-click (or an
   * Enter-key resubmit) must not start two logical submissions, and a second
   * call must never clear/rotate the idempotency key of the first while it is
   * still pending. The disabled button alone is not enough because two handlers
   * can run before either resolves.
   */
  const [submitting, setSubmitting] = createSignal(false);
  /** True when the last submit could not be confirmed: rendered as UNKNOWN, never a plain failure. */
  const [submitUnknown, setSubmitUnknown] = createSignal(false);
  /**
   * The UNKNOWN escape hatch is a two-step, explicit acknowledgement. There is no
   * backend lookup op for a withdrawal request yet (BR-9), so the UI must not make
   * releasing the guard a single reflexive click; the copy states plainly that the
   * user must have verified it out-of-band.
   */
  const [discardArmed, setDiscardArmed] = createSignal(false);

  const enabledChains = () => ws.session()?.chains.filter((chain) => chain.enabled) ?? [];
  // Withdrawal is irreversible: never default to a chain the backend did not
  // advertise as enabled. With no enabled chain the surface stays disabled.
  const chain = () => enabledChains()[0]?.id ?? null;
  const chainAvailable = () => chain() !== null;
  const denial = createMemo(() => ws.mutationDenial("withdraw"));

  const reviewMatchesUnknown = createMemo(() => {
    const unknown = unknownReview();
    const current = review();
    return unknown !== null && current !== null && sameReview(unknown, current);
  });
  /**
   * While an UNKNOWN exists, only the *same* reviewed withdrawal may be
   * re-submitted (idempotent). Authorizing different details under the same key
   * is refused until the user explicitly discards the unknown.
   */
  const reviewBlockedByUnknown = createMemo(
    () => unknownReview() !== null && !reviewMatchesUnknown(),
  );

  const amountValue = () => {
    const value = Number(amount().trim());
    return Number.isFinite(value) && value > 0 ? value : null;
  };
  const addressValid = () => destination().trim().length >= 8;
  const formValid = () => addressValid() && amountValue() !== null && chainAvailable();

  const buildReview = () => {
    if (!formValid()) return;
    const chainId = chain();
    if (chainId === null) return;
    setReview({
      chain: chainId,
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
    // Never allow a second concurrent submission: it could rotate the key of the
    // first while that one is still unresolved (duplicate irreversible transfer).
    if (submitting()) return;
    // Never authorize different details while an earlier withdrawal is
    // unresolved: it could already have been accepted.
    if (reviewBlockedByUnknown()) return;
    // One key per reviewed withdrawal. It lives across a retry (idempotent) and
    // across a cancel/re-review of an unconfirmed submission, so a withdrawal
    // that may already have been accepted cannot be duplicated by rebuilding.
    const key = reviewKey() ?? newIdempotencyKey("withdraw");
    setReviewKey(key);
    // A retry of an already-UNKNOWN withdrawal must never release the guard on a
    // determinate rejection: a gateway can reject (401/400) before the
    // idempotency store is consulted, so it does not prove the first request did
    // not commit — and a duplicate withdrawal is irreversible.
    const hadUnknown = unknownReview() !== null;
    setSubmitting(true);
    setSubmitUnknown(false);
    setSubmitState({ kind: "loading", sinceMs: ws.nowMs() });
    try {
      const result = await ws.command.send<{ request_id?: unknown }>(
        "request_withdrawal",
        {
          chain: current.chain,
          token: current.token,
          amount: current.amount,
          destination: current.destination,
          confirmation: CONFIRM_PHRASE,
        },
        { idempotencyKey: key },
      );
      const requestId = result?.request_id;
      if (typeof requestId !== "string" || requestId.length === 0) {
        throw workspaceError("protocol", "Withdrawal response was missing a request id.");
      }
      setSubmitState({
        kind: "ready",
        value: { request_id: requestId },
        freshness: { receivedAtMs: ws.nowMs(), slot: null, sourceAgeMs: 0, ttlMs: 60_000 },
      });
      setReview(null);
      setReviewKey(null);
      setUnknownReview(null);
      setDiscardArmed(false);
      setPhrase("");
    } catch (error) {
      const shape = (error as { toShape?: () => WorkspaceErrorShape }).toShape?.() ?? {
        code: "unknown" as const,
        message: "Withdrawal request failed.",
        retryable: false,
      };
      // A determinate rejection of a *first* attempt definitely did not commit:
      // rotate the key so a corrected re-review is a genuinely new
      // authorization. An ambiguous failure, a 409 conflict, or any failure of a
      // retry of an existing UNKNOWN keeps the key and stays UNKNOWN.
      if (hadUnknown || isIndeterminateOutcome(shape.code, shape.retryable) || shape.code === "freshness") {
        setSubmitUnknown(true);
        setUnknownReview(current);
      } else {
        setReviewKey(null);
        setUnknownReview(null);
      }
      setSubmitState({ kind: "error", error: shape });
    } finally {
      setSubmitting(false);
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

      <WalletLimitsPanel />

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
                    <Show when={chainAvailable()} fallback={<span class="muted">No enabled chain</span>}>
                      {chain()}
                    </Show>
                  </span>
                </label>
              </div>
              <ActionButton type="submit" disabled={!formValid() || denial() !== null}>
                Review withdrawal
              </ActionButton>
              <Show when={!chainAvailable()}>
                <ReasonNote tone="danger">
                  No enabled chain was advertised by the backend, so a withdrawal cannot be authorized.
                </ReasonNote>
              </Show>
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
              <Show when={reviewBlockedByUnknown()}>
                <ReasonNote tone="danger">
                  An earlier withdrawal is still UNKNOWN and may already have been accepted.
                  Authorizing different details now could duplicate a transfer. Verify the earlier
                  request and discard the UNKNOWN to continue.
                </ReasonNote>
                <label class="field field--checkbox">
                  <input
                    type="checkbox"
                    aria-label="I verified the earlier withdrawal out-of-band"
                    checked={discardArmed()}
                    onChange={(event) => setDiscardArmed(event.currentTarget.checked)}
                  />
                  <span class="field__label">
                    I verified in an authoritative history/explorer that the earlier withdrawal did
                    not settle.
                  </span>
                </label>
                <ActionButton
                  tone="ghost"
                  disabled={!discardArmed()}
                  onClick={() => {
                    // Explicit acknowledgement: the user takes responsibility for
                    // a genuinely new authorization.
                    setUnknownReview(null);
                    setSubmitUnknown(false);
                    setReviewKey(null);
                    setDiscardArmed(false);
                  }}
                >
                  Discard UNKNOWN and continue
                </ActionButton>
              </Show>
              <div class="ticket__actions">
                <ActionButton
                  tone="danger"
                  disabled={
                    submitting() ||
                    phrase() !== CONFIRM_PHRASE ||
                    denial() !== null ||
                    reviewBlockedByUnknown()
                  }
                  onClick={() => void submit()}
                >
                  Request withdrawal
                </ActionButton>
                <ActionButton
                  disabled={submitting()}
                  onClick={() => {
                    setReview(null);
                    setPhrase("");
                    setDiscardArmed(false);
                  }}
                >
                  Cancel
                </ActionButton>
              </div>
              <DenialNote denial={denial()} />
            </div>
          )}
        </Show>
        <Show when={submitState().kind === "loading"}>
          <ReasonNote tone="info">
            Submitting withdrawal… the outcome is pending. Do not resubmit with different details;
            the request carries a stable idempotency key.
          </ReasonNote>
        </Show>
        <Show when={submitUnknown()}>
          <ReasonNote tone="danger">
            Withdrawal outcome UNKNOWN: the request may still have reached the backend. Do not
            rebuild this withdrawal with different details — retry the same review (idempotent) or
            verify the request before authorizing anything else.
          </ReasonNote>
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
