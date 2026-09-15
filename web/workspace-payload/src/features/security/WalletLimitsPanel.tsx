import { For, Show, createEffect, createMemo, createSignal, on, type Component } from "solid-js";
import { errorState, isFresh, type DataState, type WorkspaceErrorShape } from "../../core/types";
import { workspaceError } from "../../core/errors";
import { newIdempotencyKey, isIndeterminateOutcome } from "../../core/idempotency";
import {
  diffWalletLimits,
  limitsFromView,
  parseLimitInput,
  parseWalletLimits,
  validateListInput,
  walletLimitsPayload,
  hasRelaxation,
  type WalletLimitsChange,
  type WalletLimitsEditable,
  type WalletLimitsView,
} from "../../contracts/wallet-limits";
import { createCommandResource } from "../../state/command-state";
import { useWorkspace } from "../../state/session";
import { ActionButton, Badge, KeyValue, Panel, ReasonNote } from "../../components/ui/primitives";
import { AsyncSurface, DenialNote, ErrorBlock, UnavailableBlock } from "../../components/ui/states";

const CONFIRM_PHRASE = "CONFIRM LIMIT CHANGE";
const LIMITS_TTL_MS = 60_000;

const ROUTER_OPTIONS = ["okx", "local"] as const;

interface UnknownChange {
  readonly signature: string;
  readonly key: string;
}

interface CapField {
  readonly field: string;
  readonly label: string;
  readonly aria: string;
  readonly hint: string;
}

const CAP_FIELDS: readonly CapField[] = [
  { field: "maxTradeUsd", label: "Max trade (USD)", aria: "Max trade USD", hint: "Per-order notional ceiling." },
  { field: "hourlyTurnoverUsd", label: "Hourly turnover (USD)", aria: "Hourly turnover USD", hint: "Rolling 1h traded notional." },
  { field: "dailyTurnoverUsd", label: "Daily turnover (USD)", aria: "Daily turnover USD", hint: "Rolling 24h traded notional." },
  { field: "maxBuyTaxBps", label: "Max buy tax (bps)", aria: "Max buy tax bps", hint: "Reject routes above this buy tax." },
  { field: "maxSellTaxBps", label: "Max sell tax (bps)", aria: "Max sell tax bps", hint: "Reject routes above this sell tax." },
  { field: "maxPriceImpactBps", label: "Max price impact (bps)", aria: "Max price impact bps", hint: "Hard ceiling on modelled impact." },
  { field: "maxSlippageBps", label: "Max slippage (bps)", aria: "Max slippage bps", hint: "Hard ceiling on expected slippage." },
];

function canonicalSignature(editable: WalletLimitsEditable): string {
  const payload = walletLimitsPayload(editable);
  return JSON.stringify({
    ...payload,
    allowed_chains: [...editable.allowedChains].sort(),
    allowed_routers: [...editable.allowedRouters].sort(),
    allowed_programs: [...editable.allowedPrograms].sort(),
  });
}

function directionTone(direction: WalletLimitsChange["direction"]): "warning" | "positive" | "info" {
  if (direction === "relax") return "warning";
  if (direction === "tighten") return "positive";
  return "info";
}

/**
 * W14 — trading-wallet limit & policy configuration (PRD line 86, AC9.1).
 *
 * The surface is web-only and strongly confirmed: tightening a limit saves
 * directly, while any relaxation requires an exact confirmation phrase. Every
 * write carries a stable idempotency key and an ambiguous outcome is rendered
 * UNKNOWN (never a success) with an idempotent retry and a two-step discard.
 */
export const WalletLimitsPanel: Component = () => {
  const ws = useWorkspace();
  const command = ws.command;

  // The command result is untrusted JSON: it is strictly parsed into the typed
  // view before any surface reads it, so a malformed response renders an
  // explicit protocol error rather than half-populated "limits".
  const raw = createCommandResource<unknown>(command, "get_wallet_limits", {
    capability: "wallet_limits",
    ttlMs: LIMITS_TTL_MS,
    clock: () => ws.nowMs(),
  });

  function parseView(value: unknown): WalletLimitsView | undefined {
    try {
      return parseWalletLimits(value);
    } catch {
      return undefined;
    }
  }

  const limitsState = createMemo<DataState<WalletLimitsView>>(() => {
    const state = raw.state();
    switch (state.kind) {
      case "ready": {
        const value = parseView(state.value);
        return value
          ? {
              kind: "ready",
              value,
              // The backend reports the real source age (BR-14); a hardcoded 0
              // would render a minutes-old policy as fresh and let a stale
              // baseline drive the relaxation classification.
              freshness: { ...state.freshness, slot: value.slot, sourceAgeMs: value.sourceAgeMs },
            }
          : errorState<WalletLimitsView>(
              workspaceError("protocol", "Malformed wallet-limits response."),
            );
      }
      case "stale": {
        const value = parseView(state.value);
        return value
          ? {
              kind: "stale",
              value,
              freshness: { ...state.freshness, slot: value.slot, sourceAgeMs: value.sourceAgeMs },
              reason: state.reason,
            }
          : errorState<WalletLimitsView>(
              workspaceError("protocol", "Malformed wallet-limits response."),
            );
      }
      case "loading":
        return state.prior === undefined
          ? { kind: "loading", sinceMs: state.sinceMs }
          : { kind: "loading", sinceMs: state.sinceMs, prior: parseView(state.prior) };
      case "error":
        return state.prior === undefined
          ? { kind: "error", error: state.error }
          : { kind: "error", error: state.error, prior: parseView(state.prior) };
      default:
        return state;
    }
  });

  const readDenial = createMemo(() => ws.capabilityDenial("wallet_limits"));
  const writeDenial = createMemo(() => {
    // Reference the ticking clock so session expiry (and any time-based gate)
    // is re-evaluated as time passes, not only when other signals change.
    ws.nowMs();
    return ws.mutationDenial("wallet_limits");
  });

  const [dirty, setDirty] = createSignal(false);
  const [caps, setCaps] = createSignal<Record<string, string>>({});
  const [chains, setChains] = createSignal<readonly string[]>([]);
  const [routers, setRouters] = createSignal<readonly string[]>([]);
  const [programsText, setProgramsText] = createSignal("");
  const [phrase, setPhrase] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);
  const [unknown, setUnknown] = createSignal<UnknownChange | null>(null);
  const [discardArmed, setDiscardArmed] = createSignal(false);
  const [writeError, setWriteError] = createSignal<WorkspaceErrorShape | null>(null);
  const [accepted, setAccepted] = createSignal(false);
  /** Signature of a submitted policy awaiting authoritative verification. */
  const [pendingVerify, setPendingVerify] = createSignal<{ signature: string } | null>(null);
  /** Outcome of comparing the authoritative re-read with the submitted policy. */
  const [verifyResult, setVerifyResult] = createSignal<"verified" | "not-applied" | null>(null);

  let requested = false;
  createEffect(() => {
    if (!requested && readDenial() === null) {
      requested = true;
      void raw.run();
    }
  });

  const currentView = (): WalletLimitsView | null => {
    const state = limitsState();
    if (state.kind === "ready" || state.kind === "stale") return state.value;
    if (state.kind === "loading" || state.kind === "error") return state.prior ?? null;
    return null;
  };

  function seedFrom(view: WalletLimitsView): void {
    const editable = limitsFromView(view);
    setCaps({
      maxTradeUsd: editable.maxTradeUsd === null ? "" : String(editable.maxTradeUsd),
      hourlyTurnoverUsd:
        editable.hourlyTurnoverUsd === null ? "" : String(editable.hourlyTurnoverUsd),
      dailyTurnoverUsd: editable.dailyTurnoverUsd === null ? "" : String(editable.dailyTurnoverUsd),
      maxBuyTaxBps: editable.maxBuyTaxBps === null ? "" : String(editable.maxBuyTaxBps),
      maxSellTaxBps: editable.maxSellTaxBps === null ? "" : String(editable.maxSellTaxBps),
      maxPriceImpactBps:
        editable.maxPriceImpactBps === null ? "" : String(editable.maxPriceImpactBps),
      maxSlippageBps: editable.maxSlippageBps === null ? "" : String(editable.maxSlippageBps),
    });
    setChains(editable.allowedChains);
    setRouters(editable.allowedRouters);
    setProgramsText(editable.allowedPrograms.join(", "));
  }

  // Seed the draft from an authoritative read, but never clobber edits the user
  // has already made. A successful save clears `dirty`, so the verify-read
  // re-seeds the form with the newly applied configuration.
  createEffect(
    on(
      () => limitsState(),
      (state) => {
        if ((state.kind === "ready" || state.kind === "stale") && !dirty()) {
          seedFrom(state.value);
          // A 2xx is not proof: the applied policy is only "verified" when the
          // authoritative re-read equals what was submitted. Otherwise the UI
          // says plainly that the change was not applied.
          const pending = pendingVerify();
          if (pending !== null) {
            const applied = canonicalSignature(limitsFromView(state.value)) === pending.signature;
            setVerifyResult(applied ? "verified" : "not-applied");
            setPendingVerify(null);
            setAccepted(false);
          }
        }
      },
    ),
  );

  const parsedCaps = createMemo(() => {
    const out: Record<string, number | null> = {};
    const errors: Record<string, string | null> = {};
    for (const field of CAP_FIELDS) {
      const parsed = parseLimitInput(caps()[field.field] ?? "");
      out[field.field] = parsed.value;
      errors[field.field] = parsed.error;
    }
    return { values: out, errors };
  });

  const fieldErrors = () => parsedCaps().errors;
  const programInput = createMemo(() => validateListInput(programsText()));
  const hasFieldError = () =>
    Object.values(fieldErrors()).some((error) => error !== null) ||
    programInput().error !== null;

  const draftEditable = (): WalletLimitsEditable => ({
    maxTradeUsd: parsedCaps().values.maxTradeUsd ?? null,
    hourlyTurnoverUsd: parsedCaps().values.hourlyTurnoverUsd ?? null,
    dailyTurnoverUsd: parsedCaps().values.dailyTurnoverUsd ?? null,
    maxBuyTaxBps: parsedCaps().values.maxBuyTaxBps ?? null,
    maxSellTaxBps: parsedCaps().values.maxSellTaxBps ?? null,
    maxPriceImpactBps: parsedCaps().values.maxPriceImpactBps ?? null,
    maxSlippageBps: parsedCaps().values.maxSlippageBps ?? null,
    allowedChains: chains(),
    allowedRouters: routers(),
    allowedPrograms: programInput().value,
  });

  const currentEditable = createMemo(() => {
    const view = currentView();
    return view ? limitsFromView(view) : null;
  });

  /**
   * The baseline must be fresh before a full-replacement write may be computed
   * against it. A stale baseline can misclassify a widening as a "tighten" and
   * bypass the confirmation phrase, so the surface fails closed until refreshed.
   */
  function computeBaselineFresh(): boolean {
    const state = limitsState();
    if (state.kind !== "ready" && state.kind !== "stale") return false;
    return isFresh({ ...state.freshness, slot: null }, ws.clockMs());
  }
  const baselineFresh = createMemo(() => {
    // Track the ticking clock so the TTL gate re-evaluates as time passes.
    ws.nowMs();
    return computeBaselineFresh();
  });

  const changes = createMemo(() => {
    const current = currentEditable();
    if (!current) return [];
    return diffWalletLimits(current, draftEditable());
  });
  const relaxation = createMemo(() => hasRelaxation(changes()));

  const signature = createMemo(() => canonicalSignature(draftEditable()));
  const unknownBlocked = createMemo(() => {
    const pending = unknown();
    return pending !== null && pending.signature !== signature();
  });

  const canSave = createMemo(
    () =>
      currentEditable() !== null &&
      writeDenial() === null &&
      baselineFresh() &&
      !submitting() &&
      !hasFieldError() &&
      changes().length > 0 &&
      !unknownBlocked() &&
      (!relaxation() || phrase() === CONFIRM_PHRASE),
  );

  const chainOptions = createMemo(() => {
    const advertised = ws.session()?.chains.map((chain) => chain.id) ?? [];
    return Array.from(new Set([...advertised, ...(currentEditable()?.allowedChains ?? [])]));
  });
  const routerOptions = createMemo(() =>
    Array.from(new Set([...ROUTER_OPTIONS, ...(currentEditable()?.allowedRouters ?? [])])),
  );

  const toggle = (
    setter: (value: readonly string[]) => void,
    current: () => readonly string[],
    value: string,
  ): void => {
    setDirty(true);
    setAccepted(false);
    setPendingVerify(null);
    setVerifyResult(null);
    const next = current().includes(value)
      ? current().filter((entry) => entry !== value)
      : [...current(), value];
    setter(next);
  };

  const submit = async () => {
    // Re-evaluate the authoritative gate at action time: a memo captured before
    // the session expired (or before the kill switch engaged) must not let a
    // policy write through. The form-submit path can also bypass a disabled
    // button, so this check is not redundant with `disabled`.
    const denialNow = ws.mutationDenial("wallet_limits");
    if (denialNow !== null) {
      setWriteError({ code: "auth", message: denialNow.reason, retryable: false });
      return;
    }
    // A stale baseline cannot be used to classify a relaxation: fail closed and
    // ask for a refresh instead of saving a full-replacement policy computed
    // against an out-of-date snapshot.
    if (!computeBaselineFresh()) {
      setWriteError({
        code: "freshness",
        message: "The wallet policy baseline is stale — refresh before saving.",
        retryable: false,
      });
      return;
    }
    if (!canSave()) return;
    if (submitting()) return;
    const editable = draftEditable();
    const sig = canonicalSignature(editable);
    const key = unknown()?.key ?? newIdempotencyKey("wallet_limits");
    const hadUnknown = unknown() !== null;
    setSubmitting(true);
    setWriteError(null);
    setAccepted(false);
    try {
      await command.send("set_wallet_limits", walletLimitsPayload(editable), { idempotencyKey: key });
      // A 2xx is not by itself proof the policy was applied: the surface clears
      // the guard, then re-reads the authoritative limits. If the read does not
      // reflect the change the diff simply remains visible — never a false claim.
      setUnknown(null);
      setDiscardArmed(false);
      setPhrase("");
      setDirty(false);
      setVerifyResult(null);
      setPendingVerify({ signature: sig });
      setAccepted(true);
      void raw.run();
    } catch (error) {
      const shape = (error as { toShape?: () => WorkspaceErrorShape }).toShape?.() ?? {
        code: "unknown" as const,
        message: "Limit change failed.",
        retryable: false,
      };
      // A `freshness` rejection is ambiguous for the same reason as in the
      // withdrawal surface: a gateway can reject before the idempotency store is
      // consulted, so it does not prove the write did not commit.
      if (
        hadUnknown ||
        shape.code === "freshness" ||
        isIndeterminateOutcome(shape.code, shape.retryable)
      ) {
        setUnknown({ signature: sig, key });
      } else {
        // A determinate rejection of a first attempt did not commit: a corrected
        // retry is a genuinely new change and gets a fresh key.
        setUnknown(null);
      }
      setWriteError(shape);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Panel
      title="Trading wallet limits"
      subtitle="Policy caps the trading wallet must satisfy before execution (web-only, strongly confirmed)"
      badge={
        <Badge tone={readDenial() ? "warning" : !baselineFresh() ? "warning" : writeDenial() ? "danger" : "positive"}>
          {readDenial()
            ? "NOT AVAILABLE"
            : !baselineFresh()
              ? "STALE"
              : writeDenial()
                ? "READ-ONLY"
                : "EDITABLE"}
        </Badge>
      }
      actions={
        <ActionButton disabled={readDenial() !== null} onClick={() => void raw.run()}>
          Refresh policy
        </ActionButton>
      }
    >
      <Show
        when={readDenial()}
        fallback={
          <AsyncSurface
            state={limitsState()}
            denial={readDenial()}
            nowMs={ws.nowMs()}
            onRetry={() => void raw.run()}
            unavailableDetail="Requires command op get_wallet_limits with the wallet caps, allowed chains/routers/programs, slot and source_age_ms (BR-14)."
          >
            {() => (
              <div class="panel-stack">
                <KeyValue
                  rows={[
                    {
                      key: "walletRef",
                      label: "Trading wallet",
                      value: <code>{currentView()?.walletRef ?? "not reported"}</code>,
                    },
                    {
                      key: "slot",
                      label: "Slot",
                      value: currentView()?.slot === null || currentView()?.slot === undefined ? "—" : String(currentView()!.slot),
                    },
                    {
                      key: "age",
                      label: "Source age",
                      value: `${Math.round(currentView()?.sourceAgeMs ?? 0)}ms`,
                    },
                  ]}
                />

                <Show when={!baselineFresh() && currentEditable() !== null}>
                  <ReasonNote tone="warning">
                    The policy shown is stale (older than its freshness TTL). Refresh before editing:
                    saving is disabled until the baseline is current, so a relaxation cannot be
                    misclassified against an out-of-date policy.
                  </ReasonNote>
                </Show>

                <Show when={relaxation()}>
                  <ReasonNote tone="danger">
                    This change relaxes a safety limit. Relaxations require the exact confirmation
                    phrase below before they can be saved.
                  </ReasonNote>
                </Show>

                <form
                  class="limits-config"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void submit();
                  }}
                >
                  <fieldset class="limits-config__group">
                    <legend>Caps (blank means no configured cap)</legend>
                    <div class="ticket__grid">
                      <For each={CAP_FIELDS}>
                        {(field) => (
                          <label class="field">
                            <span class="field__label">{field.label}</span>
                            <input
                              class="input"
                              inputmode="decimal"
                              autocomplete="off"
                              aria-label={field.aria}
                              data-testid={`limit-${field.field}`}
                              value={caps()[field.field] ?? ""}
                              onInput={(event) => {
                                setDirty(true);
                                setAccepted(false);
                                setPendingVerify(null);
                                setVerifyResult(null);
                                setCaps((prev) => ({ ...prev, [field.field]: event.currentTarget.value }));
                              }}
                            />
                            <span class="field__hint">{field.hint}</span>
                            <Show when={fieldErrors()[field.field]}>
                              <span class="field__error" role="alert">
                                {fieldErrors()[field.field]}
                              </span>
                            </Show>
                          </label>
                        )}
                      </For>
                    </div>
                  </fieldset>

                  <fieldset class="limits-config__group">
                    <legend>Allowed chains</legend>
                    <Show
                      when={chainOptions().length > 0}
                      fallback={<p class="muted">No chains were advertised by the backend.</p>}
                    >
                      <div class="checkbox-row">
                        <For each={chainOptions()}>
                          {(chain) => (
                            <label class="field field--checkbox">
                              <input
                                type="checkbox"
                                aria-label={`Allow chain ${chain}`}
                                checked={chains().includes(chain)}
                                onChange={() => toggle(setChains, chains, chain)}
                              />
                              <span class="field__label">{chain}</span>
                            </label>
                          )}
                        </For>
                      </div>
                    </Show>
                  </fieldset>

                  <fieldset class="limits-config__group">
                    <legend>Allowed routers</legend>
                    <div class="checkbox-row">
                      <For each={routerOptions()}>
                        {(router) => (
                          <label class="field field--checkbox">
                            <input
                              type="checkbox"
                              aria-label={`Allow router ${router}`}
                              checked={routers().includes(router)}
                              onChange={() => toggle(setRouters, routers, router)}
                            />
                            <span class="field__label">{router}</span>
                          </label>
                        )}
                      </For>
                    </div>
                  </fieldset>

                  <fieldset class="limits-config__group">
                    <legend>Allowed programs / router addresses</legend>
                    <label class="field">
                      <span class="field__label">Comma-separated allowlist (empty = none allowed)</span>
                      <textarea
                        class="input input--area"
                        aria-label="Allowed programs"
                        autocomplete="off"
                        value={programsText()}
                        onInput={(event) => {
                          setDirty(true);
                          setAccepted(false);
                          setPendingVerify(null);
                          setVerifyResult(null);
                          setProgramsText(event.currentTarget.value);
                        }}
                      />
                      <Show when={programInput().error}>
                        <span class="field__error" role="alert">
                          {programInput().error}
                        </span>
                      </Show>
                    </label>
                  </fieldset>

                  <section class="limits-config__review" aria-label="Pending changes">
                    <h3>Pending changes</h3>
                    <Show
                      when={changes().length > 0}
                      fallback={<p class="muted">No changes yet.</p>}
                    >
                      <ul class="change-list">
                        <For each={changes()}>
                          {(change) => (
                            <li class="change-list__row" data-direction={change.direction}>
                              <Badge tone={directionTone(change.direction)}>
                                {change.direction.toUpperCase()}
                              </Badge>
                              <span class="change-list__label">{change.label}</span>
                              <span class="change-list__value">
                                {change.from} → {change.to}
                              </span>
                            </li>
                          )}
                        </For>
                      </ul>
                    </Show>
                  </section>

                  <Show when={relaxation()}>
                    <label class="field">
                      <span class="field__label">Type {CONFIRM_PHRASE} to authorize a relaxation</span>
                      <input
                        class="input"
                        autocomplete="off"
                        aria-label="Limit change confirmation phrase"
                        value={phrase()}
                        onInput={(event) => setPhrase(event.currentTarget.value)}
                      />
                    </label>
                  </Show>

                  <Show when={unknownBlocked()}>
                    <ReasonNote tone="danger">
                      A previous limit change is still UNKNOWN and may already have been applied. Changing
                      the policy again could submit a different configuration under the old idempotency
                      key. Retry the same change or discard the UNKNOWN to continue.
                    </ReasonNote>
                    <label class="field field--checkbox">
                      <input
                        type="checkbox"
                        aria-label="I verified the earlier limit change out-of-band"
                        checked={discardArmed()}
                        onChange={(event) => setDiscardArmed(event.currentTarget.checked)}
                      />
                      <span class="field__label">
                        I verified in an authoritative policy view that the earlier change did not apply.
                      </span>
                    </label>
                  </Show>

                  <div class="ticket__actions">
                    <ActionButton type="submit" disabled={!canSave()}>
                      Save limits
                    </ActionButton>
                    <ActionButton
                      disabled={submitting() || !dirty()}
                      onClick={() => {
                        const view = currentView();
                        if (view) seedFrom(view);
                        setDirty(false);
                        setPhrase("");
                        setAccepted(false);
                        setWriteError(null);
                      }}
                    >
                      Reset
                    </ActionButton>
                    <Show when={unknown() !== null && unknownBlocked()}>
                      <ActionButton
                        tone="danger"
                        disabled={!discardArmed()}
                        onClick={() => {
                          setUnknown(null);
                          setDiscardArmed(false);
                          setWriteError(null);
                        }}
                      >
                        Discard UNKNOWN and continue
                      </ActionButton>
                    </Show>
                  </div>
                  <DenialNote denial={writeDenial()} />
                </form>

                <Show when={submitting()}>
                  <ReasonNote tone="info">
                    Submitting the limit change… the outcome is pending. Do not submit different values;
                    the request carries a stable idempotency key.
                  </ReasonNote>
                </Show>
                <Show when={unknown() !== null}>
                  <ReasonNote tone="danger">
                    Limit-change outcome UNKNOWN: the request may still have been applied. Retry the same
                    change (idempotent) or verify the policy before authorizing a different one.
                  </ReasonNote>
                </Show>
                <Show when={accepted()}>
                  <ReasonNote tone="info">
                    Limit change accepted by the command channel; the form is re-reading the authoritative
                    policy. Any difference still shown above is not yet confirmed.
                  </ReasonNote>
                </Show>
                <Show when={verifyResult() === "verified"}>
                  <ReasonNote tone="info">
                    Limit change verified against the authoritative policy.
                  </ReasonNote>
                </Show>
                <Show when={verifyResult() === "not-applied"}>
                  <ReasonNote tone="danger">
                    The backend still reports a different policy — the limit change was NOT applied.
                  </ReasonNote>
                </Show>
                <Show when={writeError()}>
                  <ErrorBlock error={writeError()!} />
                </Show>
              </div>
            )}
          </AsyncSurface>
        }
      >
        <UnavailableBlock
          denial={readDenial()}
          detail="Requires the wallet_limits capability and the get_wallet_limits / set_wallet_limits command ops (BR-14)."
        />
      </Show>
    </Panel>
  );
};

export default WalletLimitsPanel;
