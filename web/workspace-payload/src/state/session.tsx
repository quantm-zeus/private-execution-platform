import {
  createContext,
  createSignal,
  getOwner,
  onCleanup,
  onMount,
  useContext,
  type Accessor,
  type JSX,
} from "solid-js";
import { toWorkspaceErrorShape } from "../core/errors";
import type { RouterPreference } from "../contracts/execution";
import {
  CAPABILITY_KEYS,
  type CapabilityDenial,
  type CapabilityKey,
  type CapabilitySet,
  type ConnectionStatus,
  type DataState,
  type InstrumentRef,
  type KillSwitchState,
  idleState,
  isConnectionFresh,
  loadingState,
  unavailableState,
  errorState,
  readyState,
} from "../core/types";
import {
  bootstrapWorkspaceSession,
  type SessionBootstrapOptions,
  type WorkspaceSession,
} from "../transport/bootstrap";
import { awaitHostSessionKey, type HostSessionKey } from "../realtime/session-key";
import { UnavailableCommandClient, type CommandClient } from "../transport/command";

export interface WorkspaceStore {
  readonly state: Accessor<DataState<WorkspaceSession>>;
  readonly session: Accessor<WorkspaceSession | undefined>;
  readonly capabilities: Accessor<CapabilitySet>;
  readonly tradingEnabled: Accessor<boolean>;
  readonly killSwitch: Accessor<KillSwitchState>;
  readonly connection: Accessor<ConnectionStatus>;
  readonly nowMs: Accessor<number>;
  /**
   * Raw local wall clock, read at decision time (not the throttled `nowMs`
   * ticker). Freshness/deadline gates must use this so a background tab whose
   * interval has not fired cannot read stale state as fresh.
   */
  readonly clockMs: Accessor<number>;
  /**
   * Server-anchored clock (raw local clock + the bootstrap `server_time_ms`
   * offset). Server-issued absolute deadlines (session/quote expiry) are
   * compared against this, not a possibly-skewed local clock.
   */
  readonly serverNowMs: Accessor<number>;
  /**
   * Memory-only swap routing preference (W13). Defaults to `okx` for every new
   * private session; never written to localStorage/cookies/URL. Changing it must
   * invalidate any source-bound preview/confirmation in the caller.
   */
  readonly routerPreference: Accessor<RouterPreference>;
  setRouterPreference(preference: RouterPreference): void;
  /**
   * Memory-only target instrument shared Discover → header/chart/trade/limits/
   * execution. Reset to `null` by `reload()` (a new private session); never
   * persisted.
   */
  readonly selectedInstrument: Accessor<InstrumentRef | null>;
  setSelectedInstrument(ref: InstrumentRef | null): void;
  /** Current encrypted command channel (swapped in after the key handoff). */
  readonly command: CommandClient;
  /**
   * True once the authenticated encrypted command channel is installed. Panels
   * must not issue a command before this: the fail-closed stub answers
   * `capability_missing`, and a one-shot read would latch a permanent
   * `unavailable` state instead of waiting for the real channel.
   */
  readonly commandReady: Accessor<boolean>;
  setConnection(status: ConnectionStatus): void;
  /** Install the encrypted command channel once a session key is available. */
  setCommand(client: CommandClient): void;
  /** Release the clock ticker; called on provider unmount. */
  dispose(): void;
  reload(): void;
  /** Non-null when a read surface's capability is missing. */
  capabilityDenial(key: CapabilityKey): CapabilityDenial | null;
  /** Non-null when a mutation surface must fail closed. */
  mutationDenial(key: CapabilityKey): CapabilityDenial | null;
}

const NO_CAPABILITIES: CapabilitySet = Object.freeze(
  CAPABILITY_KEYS.reduce(
    (acc, key) => {
      acc[key] = false;
      return acc;
    },
    {} as Record<CapabilityKey, boolean>,
  ),
) as CapabilitySet;

const DISCONNECTED: ConnectionStatus = {
  phase: "idle",
  lastFrameAtMs: null,
  attempt: 0,
  nextRetryAtMs: null,
  reason: null,
};

/**
 * Bootstrap timestamps come from an unauthenticated response, so a hostile relay
 * could otherwise move the server-anchored clock arbitrarily. Never let the
 * anchor move backwards (which would extend every server-issued deadline), and
 * cap a forward correction so a lie can shift deadlines by at most this much.
 */
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

/**
 * Hard ceiling on an advertised session lifetime. `expires_at_ms` and
 * `server_time_ms` are both relay-controlled, so the *duration* is only trusted
 * up to this bound; a relay cannot mint an effectively non-expiring session.
 */
const MAX_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

function boundedServerSkew(serverTimeMs: number, localNowMs: number): number {
  const skew = serverTimeMs - localNowMs;
  if (!Number.isFinite(skew) || skew <= 0) return 0;
  return Math.min(skew, MAX_CLOCK_SKEW_MS);
}

function boundedSessionTtlMs(expiresAtMs: number, serverTimeMs: number): number {
  const ttl = expiresAtMs - serverTimeMs;
  if (!Number.isFinite(ttl) || ttl <= 0) return 0;
  return Math.min(ttl, MAX_SESSION_TTL_MS);
}

/**
 * Mutations that commit capital and therefore must fail closed when the
 * authoritative realtime state is not live (PRD circuit breaker). Read-only
 * previews and web-only withdrawal are intentionally excluded.
 */
const STATE_FRESH_MUTATIONS: readonly CapabilityKey[] = ["execute", "limits", "twap", "rfq"];

export interface CreateWorkspaceStoreOptions extends SessionBootstrapOptions {
  /** Clock tick used to recompute freshness ages. Defaults to 1000ms. */
  readonly tickMs?: number;
  /** Disable the internal ticker (tests drive `nowMs` themselves). */
  readonly manualClock?: boolean;
  /** Override the current time source. */
  readonly clock?: () => number;
  /** Encrypted command channel; defaults to a fail-closed client. */
  readonly command?: CommandClient;
  /**
   * How long the store waits for the BR-5 host key before bootstrap fails
   * closed. Defaults to 2s; the shell posts the key as soon as the payload
   * signals readiness.
   */
  readonly hostKeyTimeoutMs?: number;
}

/**
 * BR-5 handoff window. The shell only posts the keys after the payload's
 * `evergreen:workspace-ready` ping (AppShell onMount), so bootstrap must be
 * patient enough not to race that round-trip but still fail closed promptly.
 */
const DEFAULT_HOST_KEY_TIMEOUT_MS = 2_000;

export function createWorkspaceStore(options: CreateWorkspaceStoreOptions = {}): WorkspaceStore {
  const clock = options.clock ?? (() => Date.now());
  const [state, setState] = createSignal<DataState<WorkspaceSession>>(idleState());
  const [connection, setConnection] = createSignal<ConnectionStatus>(DISCONNECTED);
  const [nowMs, setNowMs] = createSignal(clock());
  // W13: OKX is the default routing preference for each new private session.
  // This is in-memory only and is reset by `reload()` (a fresh session).
  const [routerPreference, setRouterPreference] = createSignal<RouterPreference>("okx");
  // Memory-only Discover selection. Reset by `reload()` alongside the router
  // preference so a new private session never inherits a prior target.
  const [selectedInstrument, setSelectedInstrument] = createSignal<InstrumentRef | null>(null);
  /**
   * Offset between the backend clock and the local clock, captured from the
   * bootstrap `server_time_ms` anchor. Server-issued absolute timestamps (session
   * expiry) must be compared against server time, not a possibly-skewed local
   * clock, or a client clock running behind would make an expired session look
   * valid.
   */
  const [serverSkewMs, setServerSkewMs] = createSignal(0);
  /**
   * Locally derived session deadline. Computed from the advertised *duration*
   * (`expires_at_ms - server_time_ms`) rather than the absolute timestamp, so a
   * relay cannot extend a session by lying about either field.
   */
  const [sessionDeadlineMs, setSessionDeadlineMs] = createSignal(0);
  let generation = 0;
  let commandClient: CommandClient = options.command ?? new UnavailableCommandClient();
  const [commandReady, setCommandReady] = createSignal(
    !(commandClient instanceof UnavailableCommandClient),
  );
  // Stable proxy so panels that capture `ws.command` at setup still reach the
  // encrypted client once the host key handoff installs it.
  const commandProxy: CommandClient = {
    send: (op, payload, sendOptions) => commandClient.send(op, payload, sendOptions),
  };
  let ticker: number | undefined;
  // BR-5: arm the host key listener when the store is created (before
  // `reload()` runs) so a key the shell posts on readiness is not missed.
  const hostKeyAbort = new AbortController();
  let hostKeyPromise: Promise<HostSessionKey | null> | null =
    typeof window !== "undefined"
      ? awaitHostSessionKey(
          options.hostKeyTimeoutMs ?? DEFAULT_HOST_KEY_TIMEOUT_MS,
          window,
          hostKeyAbort.signal,
        )
      : null;
  // Bootstrap must never reuse sequence 0 for the same `kid` (the server's replay
  // window never resets), so each bootstrap attempt takes a strictly increasing
  // sequence. A fresh `kid` also accepts a higher first sequence.
  let bootstrapSequence = 0;

  const session = (): WorkspaceSession | undefined => {
    const current = state();
    return current.kind === "ready" || current.kind === "stale" ? current.value : current.kind === "loading" ? current.prior : current.kind === "error" ? current.prior : undefined;
  };

  const capabilities = (): CapabilitySet => {
    const current = session();
    return current ? current.capabilities : NO_CAPABILITIES;
  };

  const reload = (): void => {
    const token = ++generation;
    // A reload bootstraps a (possibly new) private session: reset the memory-only
    // routing preference to the OKX default and clear the selected instrument.
    setRouterPreference("okx");
    setSelectedInstrument(null);
    setState(loadingState<WorkspaceSession>(clock()));
    setConnection({ ...DISCONNECTED, phase: "connecting" });
    // Prefer an explicit key source from the caller; otherwise bootstrap waits on
    // the store's shared BR-5 handoff promise. An injected `session` still
    // short-circuits inside `bootstrapWorkspaceSession` before any key is needed.
    const hasExplicitKeys = Boolean(options.kid && options.c2sKeyB64 && options.s2cKeyB64);
    // Snapshot the mutable reference so the provider closure is typed non-null.
    const keyPromise = hostKeyPromise;
    const bootstrapOptions: SessionBootstrapOptions =
      options.hostKeyProvider || hasExplicitKeys || keyPromise === null
        ? options
        : { ...options, hostKeyProvider: () => keyPromise };
    // A retry/reload under the same key must not replay bootstrap sequence 0.
    const sequence = options.sequence ?? bootstrapSequence;
    if (options.sequence === undefined) bootstrapSequence += 1;
    bootstrapWorkspaceSession({ ...bootstrapOptions, sequence }).then(
      (value) => {
        if (token !== generation) return;
        setServerSkewMs(boundedServerSkew(value.serverTimeMs, clock()));
        setSessionDeadlineMs(clock() + boundedSessionTtlMs(value.expiresAtMs, value.serverTimeMs));
        if (value.capabilities.realtime) {
          setConnection({ ...DISCONNECTED, phase: "connecting" });
        } else {
          setConnection({
            phase: "offline",
            lastFrameAtMs: null,
            attempt: 0,
            nextRetryAtMs: null,
            reason: "Realtime stream capability is not available.",
          });
        }
        setState(readyState(value, {
          receivedAtMs: clock(),
          slot: null,
          sourceAgeMs: 0,
          ttlMs: 30_000,
        }));
      },
      (error: unknown) => {
        if (token !== generation) return;
        const shape = toWorkspaceErrorShape(error);
        setConnection({
          phase: shape.code === "capability_missing" ? "offline" : "degraded",
          lastFrameAtMs: null,
          attempt: 0,
          nextRetryAtMs: null,
          reason: shape.message,
        });
        setState(
          shape.code === "capability_missing"
            ? unavailableState<WorkspaceSession>("market", shape.message)
            : errorState<WorkspaceSession>(shape),
        );
      },
    );
  };

  if (!options.manualClock && typeof window !== "undefined") {
    ticker = window.setInterval(() => setNowMs(clock()), options.tickMs ?? 1_000);
    if (getOwner()) onCleanup(() => dispose());
  }

  function dispose(): void {
    hostKeyAbort.abort();
    // Drop the resolved BR-5 key reference so a torn-down workspace does not pin
    // the base64 session keys in a closure.
    hostKeyPromise = null;
    setCommandReady(false);
    if (ticker !== undefined) {
      window.clearInterval(ticker);
      ticker = undefined;
    }
  }

  return {
    state,
    session,
    capabilities,
    tradingEnabled: () => session()?.tradingEnabled === true,
    killSwitch: () => session()?.killSwitch ?? { enabled: true, reason: "Session unavailable." },
    connection,
    nowMs,
    clockMs: () => clock(),
    serverNowMs: () => clock() + serverSkewMs(),
    routerPreference,
    setRouterPreference,
    selectedInstrument,
    setSelectedInstrument,
    command: commandProxy,
    commandReady,
    setConnection,
    setCommand(client: CommandClient) {
      commandClient = client;
      setCommandReady(!(client instanceof UnavailableCommandClient));
    },
    dispose,
    reload,
    capabilityDenial(key) {
      if (capabilities()[key]) return null;
      return {
        capability: key,
        reason: `Backend capability "${key}" is not available on this deployment.`,
      };
    },
    mutationDenial(key) {
      const cap = capabilities()[key];
      if (!cap) {
        return { capability: key, reason: `Backend capability "${key}" is not available.` };
      }
      const current = session();
      if (!current) {
        return { capability: key, reason: "Workspace session is not available." };
      }
      if (!current.tradingEnabled) {
        return { capability: key, reason: "Trading is disabled by the global kill switch." };
      }
      const kill = current.killSwitch;
      if (kill?.enabled) {
        return { capability: key, reason: kill.reason ?? "Trading is halted." };
      }
      // Fresh authorization is required for every mutation: an expired session
      // must fail closed even while the capability flags still read true. The
      // deadline is derived from the advertised session duration on the local
      // clock, so neither a skewed local clock nor a relay-controlled absolute
      // timestamp can keep an expired session usable.
      if (clock() >= sessionDeadlineMs()) {
        return {
          capability: key,
          reason: "Session authorization has expired — re-authenticate before trading.",
        };
      }
      // Circuit breaker (PRD): a capital-committing mutation requires
      // authoritative realtime state. `phase` alone latches — a half-open socket
      // that stops delivering frames never flips off `live` — so the frame age is
      // the real freshness signal (see `isConnectionFresh`).
      //
      // The `realtime` bit comes from the *unauthenticated* bootstrap body, so a
      // relay that clears only that bit (while keeping execute/limits/twap/rfq)
      // must not be able to switch the breaker off by making us skip it. With no
      // advertised feed there is nothing to prove the local view is current, so
      // capital-committing mutations halt rather than pass unverified.
      if (STATE_FRESH_MUTATIONS.includes(key)) {
        if (!capabilities().realtime) {
          return {
            capability: key,
            reason:
              "Realtime state feed is not available on this deployment — trading is halted (fail closed).",
          };
        }
        // Evaluate against the current clock, not the throttled ticker signal,
        // so a tab whose interval has not fired cannot read stale state fresh.
        if (!isConnectionFresh(connection(), clock())) {
          const status = connection();
          return {
            capability: key,
            reason:
              status.phase === "live"
                ? "Realtime state is stale (no authenticated frame within the freshness window) — trading is halted until the stream resyncs."
                : `Realtime state is ${status.phase} — trading is halted until the stream resyncs.`,
          };
        }
      }
      return null;
    },
  };
}

const WorkspaceContext = createContext<WorkspaceStore>();

export function WorkspaceProvider(props: {
  options?: CreateWorkspaceStoreOptions;
  store?: WorkspaceStore;
  children: JSX.Element;
}): JSX.Element {
  const store = props.store ?? createWorkspaceStore(props.options ?? {});
  if (!props.store) {
    onMount(() => store.reload());
    onCleanup(() => store.dispose());
  }
  return <WorkspaceContext.Provider value={store}>{props.children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceStore {
  const store = useContext(WorkspaceContext);
  if (!store) throw new Error("useWorkspace must be used within a WorkspaceProvider");
  return store;
}
