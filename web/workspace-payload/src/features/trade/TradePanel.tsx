import { For, Show, createEffect, createMemo, createSignal, on, type Component, type JSX } from "solid-js";
import { formatAmount, formatBps, formatPercent, formatUsd } from "../../core/format";
import { workspaceError } from "../../core/errors";
import type {
  AmountType,
  NetEconomics,
  OrderType,
  QuotePreview,
  RouterPreference,
  TradeIntentView,
  TradeSide,
} from "../../contracts/execution";
import { parseRouterSource, routerSourceLabel } from "../../contracts/execution";
import { createCommandResource } from "../../state/command-state";
import { useWorkspace } from "../../state/session";
import { isFresh, type CapabilityDenial, type WorkspaceErrorShape } from "../../core/types";
import { isIndeterminateOutcome, newIdempotencyKey } from "../../core/idempotency";
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

/** Terminal outcome of one market submission attempt. */
export type ExecutionOutcome =
  | { readonly kind: "idle" }
  | { readonly kind: "submitting" }
  | {
      readonly kind: "submitted";
      readonly executionId: string;
      readonly quoteId: string;
      /** Routing source bound to this order (W13). */
      readonly source: RouterPreference;
    }
  /**
   * The submit could not be confirmed but the backend may still have received
   * it. Rendered as UNKNOWN, never as a plain failure: a user who reads it as
   * "failed" and re-submits a *new* intent could double-fill. The routing source
   * is part of the guard so switching source cannot clear it.
   */
  | {
      readonly kind: "unknown";
      readonly reason: string;
      readonly quoteId: string;
      readonly source: RouterPreference;
      /**
       * Client-generated idempotency key bound to this exact submission. It is
       * reused only for a retry of the *same* intent+quote+source, never as a
       * raw backend quote id (a backend that reuses quote ids across intents
       * would otherwise let an edited order masquerade as an idempotent retry).
       */
      readonly key: string;
      /** Signature of the exact previewed intent this submission was built from. */
      readonly intentSignature: string;
    }
  /** A determinate backend rejection: the order was not accepted. */
  | { readonly kind: "failed"; readonly error: WorkspaceErrorShape };

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

/**
 * Treat a missing, empty or whitespace-only token reference as absent so it
 * cannot slip past a `=== null` fail-closed gate and reach the backend.
 */
function nonBlank(value: string | null | undefined): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

/**
 * Normalised signature of the user-editable ticket plus the resolved target
 * pair. The previewed intent and the live form must agree before a submit is
 * allowed, so editing the ticket or re-targeting the shared selection after a
 * preview cannot execute an order sized for or addressed to something else.
 */
function ticketSignature(input: {
  readonly chain: string;
  readonly tokenIn: string | null;
  readonly tokenOut: string | null;
  readonly side: TradeSide;
  readonly amountType: AmountType;
  readonly amount: string;
  readonly maxSlippageBps: number | null;
  readonly maxPriceImpactBps: number | null;
  readonly maxTotalCostUsd: number | null;
}): string {
  return JSON.stringify([
    input.chain,
    input.tokenIn,
    input.tokenOut,
    input.side,
    input.amountType,
    input.amount,
    input.maxSlippageBps,
    input.maxPriceImpactBps,
    input.maxTotalCostUsd,
  ]);
}

/**
 * Signature of a backend-returned intent using the same normalized fields as the
 * live ticket, so an UNKNOWN submission can be proven to refer to the *same*
 * order (and not merely the same reused quote id) before a retry is allowed.
 */
function intentSignatureOf(intent: TradeIntentView): string {
  return ticketSignature({
    chain: intent.chain,
    tokenIn: intent.tokenIn,
    tokenOut: intent.tokenOut,
    side: intent.side,
    amountType: intent.amountType,
    amount: intent.amount,
    maxSlippageBps: intent.maxSlippageBps,
    maxPriceImpactBps: intent.maxPriceImpactBps,
    maxTotalCostUsd: intent.maxTotalCostUsd,
  });
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
  const routerPreference = ws.routerPreference;
  const [side, setSide] = createSignal<TradeSide>("buy");
  const [amount, setAmount] = createSignal("");
  const [amountType, setAmountType] = createSignal<AmountType>("usd");
  const [slippage, setSlippage] = createSignal("100");
  const [impact, setImpact] = createSignal("150");
  const [maxCost, setMaxCost] = createSignal("");
  const [confirming, setConfirming] = createSignal(false);
  // Focus management for the inline confirmation. Opening it moves focus into
  // the alertdialog so keyboard and screen-reader users land on the
  // irreversible-action evidence; Cancel returns focus to the Execute control
  // instead of dropping it on <body>.
  let executeButtonRef: HTMLButtonElement | undefined;
  let confirmDialogRef: HTMLDivElement | undefined;
  createEffect(
    on(confirming, (now, prev) => {
      if (now && !prev) queueMicrotask(() => confirmDialogRef?.focus());
      else if (!now && prev) queueMicrotask(() => executeButtonRef?.focus());
    }),
  );
  const [execState, setExecState] = createSignal<ExecutionOutcome>({ kind: "idle" });
  /** Two-step acknowledgement before releasing an UNKNOWN guard (no reconcile op yet, BR-9). */
  const [discardArmed, setDiscardArmed] = createSignal(false);
  const unknownOutcome = createMemo(() => {
    const state = execState();
    return state.kind === "unknown" ? state : null;
  });
  const preview = createCommandResource<QuotePreview>(ws.command, "preview_market_order", {
    capability: "preview",
    ttlMs: 5_000,
    // Stamp the receipt and evaluate staleness on the raw local clock (not the
    // throttled render ticker), so a backgrounded tab cannot see an expired quote
    // as fresh.
    clock: () => ws.clockMs(),
  });

  /**
   * Change the routing source. A different source is a different order, so any
   * existing preview, confirmation and source-bound executable state is
   * invalidated. An UNKNOWN outcome is deliberately NOT cleared: switching source
   * must never release an unresolved submission's guard (that would let an
   * indeterminate OKX order be followed by a fresh Local order).
   */
  const selectRouter = (preference: RouterPreference): void => {
    if (preference === routerPreference()) return;
    if (execState().kind === "submitting") return;
    setConfirming(false);
    setDiscardArmed(false);
    preview.reset();
    if (execState().kind === "failed") setExecState({ kind: "idle" });
    ws.setRouterPreference(preference);
  };

  const orderType = (): OrderType => props.orderType ?? "market";
  const parsedAmount = createMemo(() => parseAmount(amount()));
  const amountError = () =>
    amount().trim() !== "" && parsedAmount() === null ? "Enter a positive amount." : undefined;
  /**
   * A non-empty risk-limit field that does not parse must not silently become
   * `null` ("no cap"). `parseBps` maps an invalid string to null, which would
   * make a typo relax the user's own slippage/impact cap to unlimited; block the
   * preview instead. An empty field is an explicit "no cap".
   */
  const riskLimitError = createMemo<string | null>(() => {
    const bpsFields: readonly (readonly [string, string])[] = [
      ["Max slippage", slippage()],
      ["Max price impact", impact()],
    ];
    for (const [label, raw] of bpsFields) {
      const trimmed = raw.trim();
      if (trimmed === "") continue;
      const value = Number(trimmed);
      if (!Number.isFinite(value) || value < 0) {
        return `${label} must be a non-negative number of bps, or left empty for no cap.`;
      }
    }
    const cost = maxCost().trim();
    if (cost !== "") {
      const value = Number(cost);
      if (!Number.isFinite(value) || value <= 0) {
        return "Max total cost must be a positive USD amount, or left empty for no cap.";
      }
    }
    return null;
  });
  const selected = () => ws.selectedInstrument();
  const chain = (): string | null =>
    props.chain ?? selected()?.chain ?? ws.session()?.chains.find((c) => c.enabled)?.id ?? null;

  /** The session chain that owns the resolved `chain()`, if advertised and enabled. */
  const chainInfo = createMemo(() => {
    const id = chain();
    if (id === null) return undefined;
    return ws.session()?.chains.find((c) => c.id === id && c.enabled);
  });

  /** True only when the selection actually belongs to the resolved chain. */
  const selectionMatchesChain = (): boolean => {
    const ref = selected();
    return ref !== null && ref.chain === chain();
  };

  /**
   * Resolve the pair honestly: explicit props win, then the shared Discover
   * selection (the non-native leg) and the chain's advertised quote/native token
   * (BR-11). A missing leg stays `null` so the preview fails closed instead of
   * sending a null-token or fabricated intent.
   */
  const resolvedTokens = createMemo(() => {
    const info = chainInfo();
    const selectedAddress = selectionMatchesChain() ? nonBlank(selected()?.address) : null;
    if (side() === "buy") {
      return {
        tokenIn: nonBlank(props.tokenIn) ?? nonBlank(info?.nativeToken),
        tokenOut: nonBlank(props.tokenOut) ?? selectedAddress,
      };
    }
    return {
      tokenIn: nonBlank(props.tokenIn) ?? selectedAddress,
      tokenOut: nonBlank(props.tokenOut) ?? nonBlank(info?.nativeToken),
    };
  });

  /** Fail-closed reason when either resolved leg is missing, else `null`. */
  const targetError = createMemo<string | null>(() => {
    const { tokenIn, tokenOut } = resolvedTokens();
    if (tokenIn !== null && tokenOut !== null) return null;
    if (selected() === null && props.tokenIn === undefined && props.tokenOut === undefined) {
      return "Select a token in Discover to set the trade target.";
    }
    const info = chainInfo();
    if (info === undefined || info.nativeToken === null) {
      return "The chain's quote token is not advertised by the backend — previewing is disabled.";
    }
    return "Select a token in Discover or enter the counterparty token.";
  });

  const previewState = () => preview.state();

  /**
   * The untrusted preview body, only when it is a non-null, non-array object. An
   * authenticated `{ result: null }` (or any other non-object) is not a payload
   * the panel can read; every accessor below treats it as absent instead of
   * throwing inside a reactive computation and blanking the surface.
   */
  const previewValue = createMemo<Record<string, unknown> | null>(() => {
    const state = previewState();
    if (state.kind !== "ready" && state.kind !== "stale") return null;
    const value: unknown = state.value;
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  });

  /**
   * The routing source reported by a ready/stale preview. `null` means the source
   * block is missing or malformed, which is not executable.
   */
  const previewSource = createMemo(() => parseRouterSource(previewValue()?.routerSource));
  const previewSourceId = createMemo(() => previewSource()?.id ?? null);
  /**
   * The backend must use exactly the requested source: a silent substitution
   * (e.g. asking for OKX and receiving Local) is refused, never rendered as an
   * accepted quote.
   */
  const silentSourceFallback = createMemo(() => {
    const id = previewSourceId();
    return id !== null && id !== routerPreference();
  });
  const previewSourceLabel = createMemo(() => {
    const source = previewSource();
    return source === null ? null : routerSourceLabel(source.id);
  });

  /**
   * A submission whose outcome is UNKNOWN must stay bound to the exact quote
   * that produced it. Retrying *that* quote with the same idempotency key is
   * safe, but executing a freshly previewed quote under a new key is a
   * genuinely new order that could double-fill while the user believes they are
   * retrying. Block new-quote execution until the unknown outcome is resolved.
   */
  const unknownQuoteId = createMemo(() => unknownOutcome()?.quoteId ?? null);
  /** Signature of the intent the current preview would submit. */
  const previewIntentSignature = createMemo(() => {
    const state = previewState();
    if (state.kind !== "ready") return null;
    const intent = previewValue()?.intent;
    // The preview body is untrusted: a missing/non-object intent is not
    // executable and must not throw inside a reactive computation.
    if (!intent || typeof intent !== "object") return null;
    return intentSignatureOf(intent as TradeIntentView);
  });
  const previewMatchesUnknown = createMemo(() => {
    const value = previewValue();
    const unknown = unknownOutcome();
    if (unknown === null || value === null || previewState().kind !== "ready") return false;
    // The source AND the exact previewed intent are part of the identity: the
    // same quote id from a different router, or reused by the backend for a
    // different order, is a different order rather than an idempotent retry.
    return (
      value["quoteId"] === unknown.quoteId &&
      previewSourceId() === unknown.source &&
      previewIntentSignature() === unknown.intentSignature
    );
  });
  const newOrderBlocked = createMemo(() => {
    const value = previewValue();
    const unknown = unknownOutcome();
    if (unknown === null || value === null || previewState().kind !== "ready") return false;
    return (
      value["quoteId"] !== unknown.quoteId ||
      previewSourceId() !== unknown.source ||
      previewIntentSignature() !== unknown.intentSignature
    );
  });

  /**
   * Freshness of the previewed quote, including the backend-provided source age.
   * `createCommandResource` cannot know the operation's own freshness, so a
   * hardcoded `sourceAgeMs: 0` would render a 2-minute-old quote as FRESH and
   * leave it executable. A missing/non-finite `sourceAgeMs` is treated as
   * infinitely old (stale), never as fresh.
   */
  const previewFreshness = createMemo(() => {
    const state = previewState();
    const value = previewValue();
    if ((state.kind !== "ready" && state.kind !== "stale") || value === null) return null;
    const sourceAgeMs = value["sourceAgeMs"];
    const slot = value["slot"];
    return {
      ...state.freshness,
      slot: typeof slot === "number" && Number.isFinite(slot) ? slot : null,
      // `ageMs` clamps a negative age to zero, so a negative `sourceAgeMs` would
      // otherwise read as perfectly fresh; treat any non-finite or negative value
      // as infinitely old (stale).
      sourceAgeMs:
        typeof sourceAgeMs === "number" && Number.isFinite(sourceAgeMs) && sourceAgeMs >= 0
          ? sourceAgeMs
          : Number.POSITIVE_INFINITY,
    };
  });

  /**
   * Whether the preview is stale *right now* (raw local clock). Called from both
   * the reactive memo below and the imperative confirm-time re-gate, so the
   * decision never relies on a cached computation.
   */
  const previewStaleNow = (): boolean => {
    const state = previewState();
    const freshness = previewFreshness();
    if (state.kind === "stale") return true;
    if (state.kind !== "ready") return false;
    // Unknown freshness is not "not stale": refuse to execute it.
    if (freshness === null) return true;
    return !isFresh(freshness, ws.clockMs());
  };

  /**
   * Reactive view of {@link previewStaleNow}. Reading `ws.nowMs()` (the 1 s
   * clock signal) makes the gate re-evaluate as wall-clock time passes, while
   * the freshness itself is judged on the raw local clock so a throttled or
   * backgrounded tab cannot keep an expired quote executable.
   */
  const previewStale = createMemo(() => {
    ws.nowMs();
    return previewStaleNow();
  });

  /**
   * The exact intent the currently-previewed quote was built from. The
   * confirmation step must render this, never the live form signals, or the
   * dialog can describe a different trade than the one that is submitted.
   */
  const previewIntent = createMemo(() => {
    const state = previewState();
    if (state.kind !== "ready") return null;
    const intent = previewValue()?.intent;
    // The body is untrusted and shape-validated by the callers below; the cast
    // only restores the nominal view type the original value carried.
    return intent && typeof intent === "object" ? (intent as TradeIntentView) : null;
  });

  /** The exact request body the current ticket would preview. */
  const requestIntent = createMemo(() => {
    const tokens = resolvedTokens();
    return {
      chain: chain() ?? "",
      token_in: tokens.tokenIn,
      token_out: tokens.tokenOut,
      side: side(),
      amount_type: amountType(),
      amount: amount(),
      order_type: orderType(),
      max_slippage_bps: parseBps(slippage()),
      max_price_impact_bps: parseBps(impact()),
      max_total_cost_usd: parseAmount(maxCost()),
    };
  });

  const formTicketSignature = createMemo(() => {
    const tokens = resolvedTokens();
    return ticketSignature({
      chain: chain() ?? "",
      tokenIn: tokens.tokenIn,
      tokenOut: tokens.tokenOut,
      side: side(),
      amountType: amountType(),
      amount: amount(),
      maxSlippageBps: parseBps(slippage()),
      maxPriceImpactBps: parseBps(impact()),
      maxTotalCostUsd: parseAmount(maxCost()),
    });
  });

  /**
   * The previewed quote is only executable while the live ticket still matches
   * the intent it was built from — including the resolved chain and pair, so a
   * target change after previewing invalidates the executable quote. Editing the
   * ticket (without re-previewing) must not execute a quote sized differently
   * from what the user now sees.
   */
  const previewMatchesForm = createMemo(() => {
    const intent = previewIntent();
    if (intent === null) return false;
    return (
      ticketSignature({
        chain: intent.chain,
        tokenIn: intent.tokenIn,
        tokenOut: intent.tokenOut,
        side: intent.side,
        amountType: intent.amountType,
        amount: intent.amount,
        maxSlippageBps: intent.maxSlippageBps,
        maxPriceImpactBps: intent.maxPriceImpactBps,
        maxTotalCostUsd: intent.maxTotalCostUsd,
      }) === formTicketSignature()
    );
  });

  /** Editing any ticket field invalidates an open confirmation. */
  const editField = (apply: () => void): void => {
    setConfirming(false);
    apply();
  };

  const routerDenial = createMemo(() => {
    if (routerPreference() === "okx" && !ws.capabilities().okx) {
      return {
        capability: "okx" as const,
        reason:
          "OKX routing is not available on this deployment — choose Local Router or requote later. No automatic fallback is applied.",
      };
    }
    return null;
  });

  const tradingDisabled = createMemo(() => !ws.tradingEnabled());
  const executionDisabledNote = createMemo<string | null>(() =>
    tradingDisabled()
      ? "Execution is disabled on this deployment. Review and quotes still work."
      : null,
  );

  // Auto-select an actually-available route. OKX must never be the selected
  // route when the deployment does not advertise it; Local is the only
  // always-available route once preview is allowed. This never rewrites an
  // existing attempt: a ready/loading/stale quote, an in-flight submit, an
  // UNKNOWN guard or a submitted order keeps its exact source binding
  // (switching source would be a different order).
  createEffect(() => {
    if (ws.capabilities().okx) return;
    if (routerPreference() !== "okx") return;
    const state = execState();
    const attemptInFlight =
      state.kind === "submitting" || state.kind === "unknown" || state.kind === "submitted";
    const previewKind = previewState().kind;
    const quoteHeld =
      previewKind === "ready" || previewKind === "loading" || previewKind === "stale";
    if (attemptInFlight || quoteHeld) return;
    ws.setRouterPreference("local");
  });

  const usdPresets = [25, 50, 100, 250] as const;
  const applyPreset = (value: number): void => {
    editField(() => setAmount(String(value)));
  };

  const previewDenial = createMemo<CapabilityDenial | null>(() => {
    const router = routerDenial();
    if (router !== null) return router;
    const capability = ws.capabilityDenial("preview");
    if (capability !== null) return capability;
    if (chain() === null) {
      return {
        capability: "preview",
        reason: "No enabled chain was advertised by the backend — previewing is disabled.",
      };
    }
    const target = targetError();
    return target === null ? null : { capability: "preview", reason: target };
  });

  const runPreview = async () => {
    if (previewDenial() !== null) return;
    if (riskLimitError() !== null) return;
    if (parsedAmount() === null) return;
    if (execState().kind === "submitting") return;
    setConfirming(false);
    setDiscardArmed(false);
    // A new preview clears only a stale failure banner. UNKNOWN must keep
    // blocking, and a prior SUBMITTED quote keeps its `executedQuoteId` guard so
    // the same quote id can never be re-submitted even if the backend returns it
    // again for identical parameters.
    if (execState().kind === "failed") setExecState({ kind: "idle" });
    await preview.run({
      intent: requestIntent(),
      // Only the neutral first-party contract sees this; the browser never calls
      // a provider directly (W13 / architecture lock L2).
      router_preference: routerPreference(),
    });
  };

  const previewError = createMemo(() => {
    const state = previewState();
    return state.kind === "error" ? state.error : null;
  });

  /**
   * An explicit escape hatch when an OKX quote fails: the user may choose Local
   * Router themselves, but the failure must never fall back automatically. A
   * capability/auth failure is not an OKX outage, so it keeps the plain
   * unavailable/error rendering.
   */
  const showRouterEscape = createMemo(() => {
    const error = previewError();
    if (routerPreference() !== "okx" || error === null) return false;
    return error.code !== "capability_missing" && error.code !== "auth";
  });

  /**
   * The execute gate for the button. `mutationDenial` reads the raw clock for
   * session expiry and frame freshness, neither of which is a signal, so this
   * memo must also read the 1s clock signal or a denial that appears purely
   * because wall time passed would stay cached as `null` (fail open). Action
   * time still re-evaluates `ws.mutationDenial` directly (see `confirmExecute`).
   */
  const executeDenial = createMemo(() => {
    ws.nowMs();
    return ws.mutationDenial("execute");
  });

  /**
   * `revalidationRequired` is a required boolean; anything that is not exactly
   * `false` (including a stripped `undefined`) fails closed, so a relay cannot
   * turn a quote the backend intended for revalidation into an executable one.
   */
  const revalidationRequired = createMemo(() => {
    const state = previewState();
    if (state.kind !== "ready") return false;
    return previewValue()?.["revalidationRequired"] !== false;
  });

  /**
   * Whether the previewed quote has passed its server-issued absolute deadline
   * *right now*. Called from both the reactive memo and the confirm-time re-gate.
   */
  const previewExpiredNow = (): boolean => {
    const state = previewState();
    if (state.kind !== "ready") return false;
    const expiresAt = previewValue()?.["expiresAtMs"];
    if (expiresAt === null) return false;
    if (typeof expiresAt !== "number" || !Number.isFinite(expiresAt)) return true;
    return ws.serverNowMs() >= expiresAt;
  };

  /**
   * `expiresAtMs` is a server-issued absolute deadline: compare it against the
   * server-anchored clock. An absent or non-finite value is *unknown*, not
   * "never expires"; only an explicit `null` means no expiry. The memo tracks the
   * 1 s clock signal so it re-evaluates as the deadline passes.
   */
  const previewExpired = createMemo(() => {
    ws.nowMs();
    return previewExpiredNow();
  });

  /**
   * A quote that already produced a submission must not be re-submitted: the
   * same idempotency key would at best replay the earlier result and at worst
   * double-fill. Placing another order requires a fresh preview.
   */
  const executedQuoteId = createMemo(() => {
    const state = execState();
    return state.kind === "submitted" ? state.quoteId : null;
  });

  /**
   * A preview is only executable when the backend did not request explicit
   * revalidation, it has not expired, its local TTL is still fresh, and it has
   * not already been submitted.
   */
  const previewUsable = createMemo(() => {
    const state = previewState();
    if (state.kind !== "ready") return false;
    // A submit already in flight must not be raced by a second one: if the first
    // resolves UNKNOWN after a second succeeds, the UNKNOWN would be erased and
    // the user could place further orders while the first may have filled.
    if (execState().kind === "submitting") return false;
    if (routerPreference() === "okx" && !ws.capabilities().okx) return false;
    if (previewSourceId() === null) return false;
    if (silentSourceFallback()) return false;
    if (newOrderBlocked()) return false;
    if (!previewMatchesForm()) return false;
    if (revalidationRequired()) return false;
    if (previewExpired()) return false;
    if (executedQuoteId() !== null && previewValue()?.["quoteId"] === executedQuoteId()) return false;
    return !previewStale();
  });

  const previewBlockReason = createMemo(() => {
    const state = previewState();
    if (state.kind !== "ready") return null;
    if (routerPreference() === "okx" && !ws.capabilities().okx) {
      return "OKX routing is not available on this deployment — choose Local Router or requote later.";
    }
    const sourceId = previewSourceId();
    if (sourceId === null) {
      return "Backend did not report which router produced this quote — requote before executing.";
    }
    if (sourceId !== routerPreference()) {
      return `Backend used ${routerSourceLabel(sourceId)} for a ${routerSourceLabel(
        routerPreference(),
      )} request — refusing a silent fallback. Requote or switch source explicitly.`;
    }
    if (newOrderBlocked()) {
      return "An earlier submission is still UNKNOWN — verify it in Portfolio / Orders before placing a new, different order.";
    }
    if (!previewMatchesForm()) {
      return "Ticket changed since this preview — preview again so the order matches the current form.";
    }
    if (revalidationRequired()) return "Backend requires revalidation before executing — preview again.";
    if (previewExpired()) {
      const expiresAt = previewValue()?.["expiresAtMs"];
      return expiresAt === null || Number.isFinite(expiresAt)
        ? "Preview expired — preview again."
        : "Preview expiry was missing or malformed — preview again.";
    }
    if (executedQuoteId() !== null && previewValue()?.["quoteId"] === executedQuoteId()) {
      return "This preview was already submitted — preview again to place another order.";
    }
    if (previewStale()) return "Preview is stale — preview again.";
    return null;
  });

  const canExecute = createMemo(() => executeDenial() === null && previewUsable() && !confirming());

  /**
   * True only when the UNKNOWN quote is currently retryable. When it is not
   * (a different preview, an expired/stale preview, or a submit in flight) the
   * user still needs an explicit escape hatch, or the only way out would be to
   * take yet another preview.
   */
  const unknownRetryable = createMemo(
    () =>
      unknownQuoteId() !== null &&
      previewMatchesUnknown() &&
      previewUsable() &&
      // A blocked write (kill switch, stale/lapsed session) is not retryable, so
      // the discard escape must stay visible rather than trapping the user.
      executeDenial() === null,
  );

  const confirmExecute = async () => {
    const state = previewState();
    // Re-gate at confirm time: capability, kill switch, expiry and freshness can
    // all change while the confirmation panel is open. `previewStaleNow` /
    // `previewExpiredNow` re-read the raw clock instead of trusting a memo that
    // may have been cached before the deadline passed.
    if (
      state.kind !== "ready" ||
      !previewUsable() ||
      previewStaleNow() ||
      previewExpiredNow()
    ) {
      setConfirming(false);
      // Never overwrite an UNKNOWN or in-flight outcome with a generic failure:
      // the UNKNOWN must keep blocking, and `submitting` is a guard that keeps a
      // racing second submit from erasing a later UNKNOWN.
      const current = execState().kind;
      if (current !== "unknown" && current !== "submitting") {
        setExecState({
          kind: "failed",
          error: {
            code: "freshness",
            message: previewBlockReason() ?? "Preview is no longer executable.",
            retryable: true,
          },
        });
      }
      return;
    }
    // Re-evaluate the mutation gate fresh at action time instead of trusting the
    // memo: the session deadline or realtime freshness can lapse purely with wall
    // time, and the memo may have been computed before that (fail open).
    const denial = ws.mutationDenial("execute");
    if (denial !== null) {
      setConfirming(false);
      // Never clear an UNKNOWN or in-flight outcome: a denial that appears at
      // action time must not erase a submission that may already have committed.
      const current = execState().kind;
      if (current !== "unknown" && current !== "submitting") {
        setExecState({
          kind: "failed",
          error: { code: "capability_missing", message: denial.reason, retryable: false },
        });
      }
      return;
    }
    setConfirming(false);
    const submittedQuoteId = previewValue()?.["quoteId"];
    if (typeof submittedQuoteId !== "string" || submittedQuoteId.length === 0) {
      setExecState({
        kind: "failed",
        error: {
          code: "protocol",
          message: "Backend did not return a quote id — requote before executing.",
          retryable: true,
        },
      });
      return;
    }
    const source = previewSourceId();
    if (source === null) {
      // `previewUsable` already requires a reported source; this is a defensive
      // fail-closed guard so an execute can never be sent without a bound source.
      setExecState({
        kind: "failed",
        error: {
          code: "protocol",
          message: "Routing source was not reported — requote before executing.",
          retryable: true,
        },
      });
      return;
    }
    const previewIntentValue = previewValue()?.["intent"];
    const submittedIntentSignature =
      previewIntentValue && typeof previewIntentValue === "object"
        ? intentSignatureOf(previewIntentValue as TradeIntentView)
        : "";
    // Capture whether this is a retry of an already-UNKNOWN submission: a
    // determinate rejection on the retry must not release that guard, because a
    // gateway can reject before the idempotency store is consulted.
    const priorUnknown = unknownOutcome();
    const retryingUnknown = priorUnknown !== null && previewMatchesUnknown();
    const hadUnknown = priorUnknown !== null;
    // A retry of the exact same unknown submission reuses its client-generated
    // key. Any other attempt — including a same-quote-id preview of a different
    // intent — gets a fresh key, so key rotation does not depend on the backend
    // issuing a new quote id.
    const requestKey = retryingUnknown ? priorUnknown.key : newIdempotencyKey("market");
    setExecState({ kind: "submitting" });
    try {
      const result = await ws.command.send<{
        execution_id?: unknown;
        router_source?: unknown;
      }>(
        "execute_market_order",
        // The routing source is bound into the write so the backend executes the
        // exact source the user reviewed (W13); it cannot be re-routed silently.
        { quote_id: submittedQuoteId, router_preference: source },
        // The idempotency key belongs in the transport envelope (BR-3), not only
        // inside the operation payload; a retry of this exact submission dedupes.
        { idempotencyKey: requestKey },
      );
      const executionId = result?.execution_id;
      if (typeof executionId !== "string" || executionId.length === 0) {
        // A 200 without an execution id is a malformed/unbound response; treat
        // it as UNKNOWN rather than rendering a false success.
        throw workspaceError("protocol", "Execution response was missing an execution id.");
      }
      // The backend must echo the source it actually executed (BR-10). A
      // mismatch, an absent echo or a malformed echo all leave the true route
      // unproven, so the outcome is UNKNOWN rather than a confident success that
      // attributes the order to a route we cannot substantiate.
      const echoed = parseRouterSource(result?.router_source);
      if (echoed === null || echoed.id !== source) {
        throw workspaceError("protocol", "Execution source was not confirmed by the backend.");
      }
      setExecState({ kind: "submitted", executionId, quoteId: submittedQuoteId, source });
    } catch (error) {
      const shape = (error as { toShape?: () => WorkspaceErrorShape }).toShape?.() ?? {
        code: "unknown" as const,
        message: "Execution failed.",
        retryable: false,
      };
      // Fail honest: an unconfirmed submit is UNKNOWN, not failed. The same
      // quote + idempotency key still dedupes if the user retries this preview.
      // An existing UNKNOWN always stays guarded, whatever the retry returns.
      if (hadUnknown || isIndeterminateOutcome(shape.code, shape.retryable)) {
        setExecState({
          kind: "unknown",
          reason: shape.message,
          quoteId: submittedQuoteId,
          source,
          key: requestKey,
          intentSignature: submittedIntentSignature,
        });
      } else {
        // A determinate rejection of a *first* attempt must not be replayable
        // with the same key: drop the preview so the next attempt requires a
        // fresh quote (and thus a new idempotency key).
        preview.reset();
        setExecState({ kind: "failed", error: shape });
      }
    }
  };

  const failedError = createMemo(() => {
    const state = execState();
    return state.kind === "failed" ? state.error : null;
  });
  const submittedOutcome = createMemo(() => {
    const state = execState();
    return state.kind === "submitted" ? state : null;
  });

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
              class="chip-button chip-button--buy"
              aria-pressed={side() === "buy"}
              onClick={() => editField(() => setSide("buy"))}
            >
              Buy
            </button>
            <button
              type="button"
              class="chip-button chip-button--sell"
              aria-pressed={side() === "sell"}
              onClick={() => editField(() => setSide("sell"))}
            >
              Sell
            </button>
          </div>
          <p class="ticket__pair" data-testid="trade-target">
            <Show when={selected()} fallback={<span class="muted">Select a token to trade</span>}>
              {(instrument) => (
                <span>
                  <strong>{instrument().symbol}</strong>
                  <span class="muted"> · {instrument().chain}</span>
                </span>
              )}
            </Show>
          </p>
          <div class="ticket__amount">
            <label class="field field--amount">
              <span class="field__label">Amount</span>
              <div class="ticket__amount-row">
                <input
                  class="input"
                  inputmode="decimal"
                  aria-label="Amount"
                  value={amount()}
                  onInput={(event) => editField(() => setAmount(event.currentTarget.value))}
                />
                <select
                  class="input ticket__unit"
                  aria-label="Amount unit"
                  value={amountType()}
                  onChange={(event) =>
                    editField(() => setAmountType(event.currentTarget.value as AmountType))
                  }
                >
                  <option value="usd">USD</option>
                  <option value="stablecoin">USDC</option>
                  <option value="token">Token</option>
                </select>
              </div>
              {amountError() ? (
                <span class="field__error" role="alert">
                  {amountError()}
                </span>
              ) : null}
            </label>
            <Show when={amountType() !== "token"}>
              <div class="preset-row" role="group" aria-label="Amount presets">
                <For each={usdPresets}>
                  {(preset) => (
                    <button
                      type="button"
                      class="preset-chip"
                      data-testid={`amount-preset-${preset}`}
                      onClick={() => applyPreset(preset)}
                    >
                      ${preset}
                    </button>
                  )}
                </For>
              </div>
            </Show>
          </div>

          <details class="ticket__advanced" data-testid="ticket-advanced">
            <summary>Advanced</summary>
            <div class="ticket__advanced-body">
              <div class="ticket__side" role="group" aria-label="Routing source">
                <span class="field__label">Routing source</span>
                <button
                  type="button"
                  class="chip-button"
                  aria-pressed={routerPreference() === "okx"}
                  disabled={!ws.capabilities().okx || execState().kind === "submitting"}
                  title={
                    ws.capabilities().okx
                      ? "Route through OKX"
                      : "OKX routing is not available on this deployment"
                  }
                  onClick={() => selectRouter("okx")}
                >
                  OKX
                </button>
                <button
                  type="button"
                  class="chip-button"
                  aria-pressed={routerPreference() === "local"}
                  disabled={execState().kind === "submitting"}
                  onClick={() => selectRouter("local")}
                >
                  Local Router
                </button>
              </div>
              <div class="ticket__grid">
                <label class="field">
                  <span class="field__label">Max slippage (bps)</span>
                  <input
                    class="input"
                    inputmode="numeric"
                    aria-label="Max slippage bps"
                    value={slippage()}
                    onInput={(event) => editField(() => setSlippage(event.currentTarget.value))}
                  />
                </label>
                <label class="field">
                  <span class="field__label">Max price impact (bps)</span>
                  <input
                    class="input"
                    inputmode="numeric"
                    aria-label="Max price impact bps"
                    value={impact()}
                    onInput={(event) => editField(() => setImpact(event.currentTarget.value))}
                  />
                </label>
                <label class="field">
                  <span class="field__label">Max total cost (USD, optional)</span>
                  <input
                    class="input"
                    inputmode="decimal"
                    aria-label="Max total cost usd"
                    value={maxCost()}
                    onInput={(event) => editField(() => setMaxCost(event.currentTarget.value))}
                  />
                </label>
              </div>
              <p class="field__hint">
                Safe defaults: 100 bps slippage, 150 bps price impact, no total-cost cap.
              </p>
            </div>
          </details>

          <div class="ticket__actions ticket__actions--primary">
            <Badge tone={routerPreference() === "okx" ? "info" : "muted"}>
              Route {routerSourceLabel(routerPreference())}
            </Badge>
            <ActionButton
              type="submit"
              tone="primary"
              disabled={
                parsedAmount() === null ||
                previewDenial() !== null ||
                riskLimitError() !== null ||
                execState().kind === "submitting"
              }
            >
              Review order
            </ActionButton>
          </div>
          <DenialNote denial={previewDenial()} />
          <Show when={riskLimitError()}>
            {(message) => (
              <span class="field__error" role="alert">
                {message()}
              </span>
            )}
          </Show>
        </form>
        <Show when={showRouterEscape()}>
          <div class="state-block state-block--error" role="alert" data-testid="okx-unavailable">
            <p class="state-block__title">OKX routing unavailable</p>
            <p class="state-block__detail">
              The preferred OKX route could not be quoted. No fallback is applied automatically —
              requote, or explicitly switch to Local Router.
            </p>
            <ActionButton onClick={() => selectRouter("local")}>Use Local Router</ActionButton>
          </div>
        </Show>
      </Panel>

      <Panel
        title="Net economics & route"
        subtitle="Every cost is part of the route score"
        badge={
          <Show when={previewFreshness()}>
            {(freshness) => <FreshnessBadge freshness={freshness()} nowMs={ws.nowMs()} />}
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
              <p class="muted" data-testid="preview-route-source">
                route source {previewSourceLabel() ?? "—"}
              </p>
              <details class="quote-details">
                <summary>Details</summary>
                <p class="muted">
                  slot {quote.slot ?? "—"} · source age {quote.sourceAgeMs}ms · revalidation{" "}
                  {quote.revalidationRequired ? "required" : "not required"}
                </p>
              </details>
            </div>
          )}
        </AsyncSurface>
      </Panel>

      <Panel title="Execute" subtitle="Fails closed unless capability, trading gate and freshness agree">
        <Show
          when={!confirming()}
          fallback={
            <div
              class="panel-stack"
              role="alertdialog"
              aria-label="Confirm market execution"
              tabindex="-1"
              ref={confirmDialogRef}
            >
              <Show
                when={previewIntent()}
                fallback={<ReasonNote tone="warning">Preview is no longer available — preview again.</ReasonNote>}
              >
                {(intent) => (
                  <ReasonNote tone="danger" live="assertive">
                    Confirm market {intent().side} for {intent().amount} {intent().amountType} on{" "}
                    {intent().chain}
                    {intent().tokenIn || intent().tokenOut
                      ? ` (${intent().tokenIn ?? "native"} → ${intent().tokenOut ?? "native"})`
                      : ""}{" "}
                    via {previewSourceLabel() ?? "—"}. Execution cannot be undone.
                  </ReasonNote>
                )}
              </Show>
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
              <Show
                when={executionDisabledNote()}
                fallback={<DenialNote denial={executeDenial()} />}
              >
                {(note) => (
                  <ReasonNote tone="warning" live="polite">
                    <span data-testid="execution-disabled">{note()}</span>
                  </ReasonNote>
                )}
              </Show>
            </div>
          }
        >
          <ActionButton
            ref={(element) => (executeButtonRef = element)}
            tone="primary"
            disabled={!canExecute()}
            onClick={() => setConfirming(true)}
          >
            Execute {side()}
          </ActionButton>
        </Show>
        <Show when={!confirming()}>
          <Show when={executionDisabledNote()} fallback={<DenialNote denial={executeDenial()} />}>
            {(note) => (
              <ReasonNote tone="warning" live="polite">
                <span data-testid="execution-disabled">{note()}</span>
              </ReasonNote>
            )}
          </Show>
        </Show>
        <Show when={!confirming() && previewBlockReason() && !tradingDisabled()}>
          <ReasonNote tone="warning">{previewBlockReason()}</ReasonNote>
        </Show>
        <Show when={execState().kind === "submitting"}>
          <ReasonNote tone="info">
            Submitting… the outcome is pending. Do not resubmit; this order carries a stable
            idempotency key.
          </ReasonNote>
        </Show>
        <Show when={failedError()}>
          {(error) => <ErrorBlock error={error()} />}
        </Show>
        <Show when={unknownOutcome()}>
          {(outcome) => (
            <div class="state-block state-block--error" role="alert">
              <p class="state-block__title">Execution outcome unknown</p>
              <p class="state-block__detail">
                {outcome().reason} The request may still have reached the backend, so this order may
                already be placed. Do not start a new order. Check Portfolio / Orders before
                doing anything else; retrying the same preview is idempotent and cannot create a
                second trade. Changing the routing source would be a different order and does not
                clear this guard.
              </p>
              <p class="state-block__meta">
                quote {outcome().quoteId} via {routerSourceLabel(outcome().source)}
              </p>
              <ActionButton
                disabled={!previewMatchesUnknown() || !previewUsable() || executeDenial() !== null}
                onClick={() => void confirmExecute()}
              >
                Retry same order (idempotent)
              </ActionButton>
              <Show when={unknownQuoteId() !== null && !unknownRetryable()}>
                <p class="state-block__detail" data-testid="new-order-blocked">
                  A different preview is loaded (or the previous one is no longer retryable), but the
                  earlier submission is still UNKNOWN. Executing anything now would be a second,
                  unrelated order and could double-fill. Verify the earlier order in Portfolio /
                  Orders first.
                </p>
                <label class="field field--checkbox">
                  <input
                    type="checkbox"
                    aria-label="I verified the earlier order out-of-band"
                    checked={discardArmed()}
                    onChange={(event) => setDiscardArmed(event.currentTarget.checked)}
                  />
                  <span class="field__label">
                    I verified in an authoritative order list/explorer that the earlier order did not
                    fill.
                  </span>
                </label>
                <ActionButton
                  tone="ghost"
                  disabled={!discardArmed()}
                  onClick={() => {
                    setDiscardArmed(false);
                    setExecState({ kind: "idle" });
                  }}
                >
                  Discard UNKNOWN and continue
                </ActionButton>
              </Show>
            </div>
          )}
        </Show>
        <Show when={submittedOutcome()}>
          {(outcome) => (
            <ReasonNote tone="info">
              Submitted execution {outcome().executionId} via {routerSourceLabel(outcome().source)}.
              Track it in the Execution view.
            </ReasonNote>
          )}
        </Show>
      </Panel>
    </div>
  );
};

export default TradePanel;
