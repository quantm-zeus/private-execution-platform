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
import {
  CAPABILITY_KEYS,
  type CapabilityDenial,
  type CapabilityKey,
  type CapabilitySet,
  type ConnectionStatus,
  type DataState,
  type KillSwitchState,
  idleState,
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
import { UnavailableCommandClient, type CommandClient } from "../transport/command";

export interface WorkspaceStore {
  readonly state: Accessor<DataState<WorkspaceSession>>;
  readonly session: Accessor<WorkspaceSession | undefined>;
  readonly capabilities: Accessor<CapabilitySet>;
  readonly tradingEnabled: Accessor<boolean>;
  readonly killSwitch: Accessor<KillSwitchState>;
  readonly connection: Accessor<ConnectionStatus>;
  readonly nowMs: Accessor<number>;
  /** Current encrypted command channel (swapped in after the key handoff). */
  readonly command: CommandClient;
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

export interface CreateWorkspaceStoreOptions extends SessionBootstrapOptions {
  /** Clock tick used to recompute freshness ages. Defaults to 1000ms. */
  readonly tickMs?: number;
  /** Disable the internal ticker (tests drive `nowMs` themselves). */
  readonly manualClock?: boolean;
  /** Override the current time source. */
  readonly clock?: () => number;
  /** Encrypted command channel; defaults to a fail-closed client. */
  readonly command?: CommandClient;
}

export function createWorkspaceStore(options: CreateWorkspaceStoreOptions = {}): WorkspaceStore {
  const clock = options.clock ?? (() => Date.now());
  const [state, setState] = createSignal<DataState<WorkspaceSession>>(idleState());
  const [connection, setConnection] = createSignal<ConnectionStatus>(DISCONNECTED);
  const [nowMs, setNowMs] = createSignal(clock());
  let generation = 0;
  let commandClient: CommandClient = options.command ?? new UnavailableCommandClient();
  let ticker: number | undefined;

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
    setState(loadingState<WorkspaceSession>(clock()));
    setConnection({ ...DISCONNECTED, phase: "connecting" });
    bootstrapWorkspaceSession(options).then(
      (value) => {
        if (token !== generation) return;
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
    get command() {
      return commandClient;
    },
    setConnection,
    setCommand(client: CommandClient) {
      commandClient = client;
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
      if (!session()?.tradingEnabled) {
        return { capability: key, reason: "Trading is disabled by the global kill switch." };
      }
      const kill = session()?.killSwitch;
      if (kill?.enabled) {
        return { capability: key, reason: kill.reason ?? "Trading is halted." };
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
