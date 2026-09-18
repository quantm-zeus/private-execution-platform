import { render } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import type { InstrumentRef } from "../../core/types";
import type { CommandClient } from "../../transport/command";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import { WorkstationProvider } from "../../state/workstation";

export const SOL_A = {
  chain: "solana",
  address: "TokenAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  symbol: "AAA",
} as const;

export const SOL_B = {
  chain: "solana",
  address: "TokenBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  symbol: "BBB",
} as const;

export function sessionWith(capabilities: Record<string, boolean> = {}, tradingEnabled = false) {
  return parseWorkspaceSession({
    protocol_version: 1,
    capabilities: {
      market: true,
      realtime: true,
      token_intelligence: true,
      ...capabilities,
    },
    trading_enabled: tradingEnabled,
    kill_switch: { enabled: false, reason: null },
    chains: [
      {
        id: "solana",
        display: "Solana",
        enabled: true,
        native_token: "So11111111111111111111111111111111111111112",
      },
    ],
    session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
    server_time_ms: 1_699_999_000_000,
  });
}

/** A command client with a default fail-closed set of token-intelligence reads. */
export function makeCommand(
  handlers: Record<string, (payload?: unknown) => unknown> = {},
): CommandClient {
  return {
    async send<T>(op: string, payload?: unknown): Promise<T> {
      if (Object.prototype.hasOwnProperty.call(handlers, op)) {
        return handlers[op]!(payload) as T;
      }
      switch (op) {
        case "set_realtime_target":
          return { accepted: true } as unknown as T;
        case "get_token_holders":
          return { chain: SOL_A.chain, address: SOL_A.address, holders: [] } as unknown as T;
        case "get_token_about":
          return { token: { chain: SOL_A.chain, address: SOL_A.address } } as unknown as T;
        case "get_token_activity":
          return { chain: SOL_A.chain, address: SOL_A.address, events: [] } as unknown as T;
        case "get_execution_progress":
          return null as unknown as T;
        default:
          throw new Error(`unexpected op ${op}`);
      }
    },
  };
}

export function createStore(
  command: CommandClient = makeCommand(),
  options: {
    capabilities?: Record<string, boolean>;
    selected?: InstrumentRef | null;
    /** When true, no command client is installed: the channel stays fail-closed. */
    failClosed?: boolean;
    /** Test-only: enable the trading gate (production stays false). */
    tradingEnabled?: boolean;
  } = {},
) {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_700_000_000_000,
    session: sessionWith(options.capabilities, options.tradingEnabled),
  });
  if (!options.failClosed) store.setCommand(command);
  store.reload();
  if (options.selected) store.setSelectedInstrument(options.selected);
  return store;
}

export function renderStation(
  store: ReturnType<typeof createStore>,
  ui: () => JSX.Element,
): ReturnType<typeof render> {
  return render(() => (
    <WorkspaceProvider store={store}>
      <WorkstationProvider ws={store}>{ui()}</WorkstationProvider>
    </WorkspaceProvider>
  ));
}
