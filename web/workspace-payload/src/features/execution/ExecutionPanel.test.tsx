import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { ExecutionPanel } from "./ExecutionPanel";
import { WorkspaceError } from "../../core/types";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import type { CommandClient } from "../../transport/command";
import type { RfqView } from "../../contracts/execution";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const rfq: RfqView = {
  rfqId: "rfq-1",
  state: "running",
  bestSolver: "solver-b",
  legs: [
    { solver: "solver-a", amountOut: "100", netOutput: 98, latencyMs: 40, viable: true },
    { solver: "solver-b", amountOut: "101", netOutput: 99.5, latencyMs: 55, viable: true },
    { solver: "solver-c", amountOut: "90", netOutput: 80, latencyMs: null, viable: false },
  ],
};

const EXEC_QUOTE_TOKEN = "USDC";
const EXEC_SELECTED_TOKEN = "0xselected";

function storeWith(command: CommandClient, tradingEnabled: boolean) {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      // TWAP/RFQ are capital-committing: the fixture advertises the realtime feed.
      capabilities: { twap: true, rfq: true, market: true, realtime: true },
      trading_enabled: tradingEnabled,
      kill_switch: { enabled: false, reason: null },
      chains: [
        { id: "base", display: "Base", enabled: true, native_token: EXEC_QUOTE_TOKEN },
      ],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  // The bootstrap microtask resolves before this one, so the live connection
  // wins and mutation tests exercise the trading path, not the offline gate.
  const reload = store.reload.bind(store);
  (store as { reload: () => void }).reload = () => {
    reload();
    queueMicrotask(() => {
      store.setConnection({
        phase: "live",
        lastFrameAtMs: 1_000,
        attempt: 0,
        nextRetryAtMs: null,
        reason: null,
      });
      store.setSelectedInstrument({
        chain: "base",
        address: EXEC_SELECTED_TOKEN,
        symbol: "TKN",
      });
    });
  };
  store.reload();
  return store;
}

describe("ExecutionPanel", () => {
  afterEach(() => cleanup());

  it("fails TWAP and RFQ closed while trading is disabled", async () => {
    const store = storeWith({ async send<T>(): Promise<T> { throw new Error("unused"); } }, false);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));
    expect((screen.getByRole("button", { name: /start adaptive twap/i }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: /request quotes/i }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("resolves the target tokens on TWAP and RFQ requests", async () => {
    const twapPayloads: unknown[] = [];
    const rfqPayloads: unknown[] = [];
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown): Promise<T> {
        if (op === "get_execution_progress") {
          return {
            executionId: "ex-0",
            kind: "twap",
            state: "completed",
            chunksTotal: 1,
            chunksDone: 1,
            filledAmount: "100",
            remainingAmount: "0",
            realizedVsEstimateBps: 0,
            haltReason: null,
          } as unknown as T;
        }
        if (op === "start_twap") {
          twapPayloads.push(payload);
          return {
            executionId: "ex-1",
            kind: "twap",
            state: "running",
            chunksTotal: 1,
            chunksDone: 0,
            filledAmount: null,
            remainingAmount: null,
            realizedVsEstimateBps: null,
            haltReason: null,
          } as unknown as T;
        }
        if (op === "submit_rfq") {
          rfqPayloads.push(payload);
          return rfq as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));

    fireEvent.input(screen.getByLabelText("TWAP total amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: /start adaptive twap/i }));
    await flush();
    expect(twapPayloads[0]).toMatchObject({
      chain: "base",
      tokenIn: EXEC_QUOTE_TOKEN,
      tokenOut: EXEC_SELECTED_TOKEN,
    });

    fireEvent.click(screen.getByRole("button", { name: /request quotes/i }));
    await flush();
    expect(rfqPayloads[0]).toMatchObject({
      chain: "base",
      token_in: EXEC_QUOTE_TOKEN,
      token_out: EXEC_SELECTED_TOKEN,
    });
  });

  it("surfaces a TWAP start failure instead of silently doing nothing", async () => {
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        if (op === "get_execution_progress") {
          return {
            executionId: "ex-0",
            kind: "twap",
            state: "completed",
            chunksTotal: 1,
            chunksDone: 1,
            filledAmount: "100",
            remainingAmount: "0",
            realizedVsEstimateBps: 0,
            haltReason: null,
          } as unknown as T;
        }
        throw new WorkspaceError({ code: "server", message: "TWAP rejected by backend.", retryable: true });
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("TWAP total amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: /start adaptive twap/i }));
    await flush();
    expect(screen.getByText(/TWAP rejected by backend/i)).toBeTruthy();
  });

  it("renders solver legs with a BEST badge when quotes are available", async () => {
    const client: CommandClient = {
      async send<T>(): Promise<T> {
        return rfq as unknown as T;
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));
    fireEvent.click(screen.getByRole("button", { name: /request quotes/i }));
    await flush();
    expect(screen.getByText("BEST")).toBeTruthy();
    expect(screen.getAllByText("solver-b").length).toBeGreaterThan(0);
  });

  it("loads current execution progress once the twap capability is available", async () => {
    const ops: string[] = [];
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        ops.push(op);
        return {
          executionId: "ex-1",
          kind: "twap",
          state: "running",
          chunksTotal: 4,
          chunksDone: 1,
          filledAmount: "25",
          remainingAmount: "75",
          realizedVsEstimateBps: -3,
          haltReason: null,
        } as unknown as T;
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));
    await flush();
    await flush();
    expect(ops).toContain("get_execution_progress");
    expect(screen.getByText("1/4")).toBeTruthy();
  });

  it("keeps a TWAP UNKNOWN guarded and requires a two-step discard", async () => {
    const keys: (string | undefined)[] = [];
    let mode: "network" | "auth" = "network";
    const client: CommandClient = {
      async send<T>(
        op: string,
        _payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "get_execution_progress") {
          return {
            executionId: "ex-0",
            kind: "twap",
            state: "completed",
            chunksTotal: 1,
            chunksDone: 1,
            filledAmount: "100",
            remainingAmount: "0",
            realizedVsEstimateBps: 0,
            haltReason: null,
          } as unknown as T;
        }
        if (op === "start_twap") {
          keys.push(options?.idempotencyKey);
          throw new WorkspaceError({
            code: mode,
            message: mode === "network" ? "offline" : "unauthorized",
            retryable: mode === "network",
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("TWAP total amount"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: /start adaptive twap/i }));
    await flush();
    expect(screen.getByText(/TWAP submission outcome UNKNOWN/i)).toBeTruthy();

    // A determinate rejection of the retry must not release the guard or rotate
    // the key; the first TWAP may already be running.
    mode = "auth";
    fireEvent.click(screen.getByRole("button", { name: /retry same request/i }));
    await flush();
    expect(screen.getByText(/TWAP submission outcome UNKNOWN/i)).toBeTruthy();
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);

    // Releasing the guard is explicitly two-step.
    const discard = screen.getByRole("button", {
      name: /discard unknown and continue/i,
    }) as HTMLButtonElement;
    expect(discard.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/verified the earlier TWAP/i));
    await flush();
    expect(discard.disabled).toBe(false);
    fireEvent.click(discard);
    await flush();
    expect(screen.queryByText(/TWAP submission outcome UNKNOWN/i)).toBeNull();
  });

  it("refuses a second concurrent TWAP start while the first is in flight", async () => {
    const keys: (string | undefined)[] = [];
    let release!: (value: unknown) => void;
    const pending = new Promise((resolve) => {
      release = resolve;
    });
    const client: CommandClient = {
      async send<T>(
        op: string,
        _payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "get_execution_progress") {
          return {
            executionId: "ex-0",
            kind: "twap",
            state: "completed",
            chunksTotal: 1,
            chunksDone: 1,
            filledAmount: "100",
            remainingAmount: "0",
            realizedVsEstimateBps: 0,
            haltReason: null,
          } as unknown as T;
        }
        if (op === "start_twap") {
          keys.push(options?.idempotencyKey);
          await pending;
          return {
            executionId: "ex-1",
            kind: "twap",
            state: "running",
            chunksTotal: 1,
            chunksDone: 0,
            filledAmount: null,
            remainingAmount: null,
            realizedVsEstimateBps: null,
            haltReason: null,
          } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("TWAP total amount"), { target: { value: "100" } });
    const start = () =>
      screen.getByRole("button", { name: /start adaptive twap/i }) as HTMLButtonElement;
    fireEvent.click(start());
    expect(start().disabled).toBe(true);
    // Solid's delegated handler ignores a disabled node; force it enabled to
    // exercise the action-time guard (without it these would start a second TWAP).
    const forceStart = () => {
      start().disabled = false;
      fireEvent.click(start());
    };
    forceStart();
    forceStart();
    await flush();
    expect(keys).toHaveLength(1);
    release(undefined);
    await flush();
    expect(keys).toHaveLength(1);
  });

  it("keeps an RFQ UNKNOWN guarded when a retry is rejected determinately", async () => {
    const keys: (string | undefined)[] = [];
    let mode: "network" | "auth" = "network";
    const client: CommandClient = {
      async send<T>(
        op: string,
        _payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "get_execution_progress") {
          return {
            executionId: "ex-0",
            kind: "twap",
            state: "completed",
            chunksTotal: 1,
            chunksDone: 1,
            filledAmount: "100",
            remainingAmount: "0",
            realizedVsEstimateBps: 0,
            haltReason: null,
          } as unknown as T;
        }
        if (op === "submit_rfq") {
          keys.push(options?.idempotencyKey);
          throw new WorkspaceError({
            code: mode,
            message: mode === "network" ? "offline" : "unauthorized",
            retryable: mode === "network",
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));
    fireEvent.click(screen.getByRole("button", { name: /request quotes/i }));
    await flush();
    expect(screen.getByText(/RFQ outcome UNKNOWN/i)).toBeTruthy();

    // A determinate rejection on a retry of the unresolved RFQ must not release
    // the guard or rotate the key: the first request may already be in flight.
    mode = "auth";
    fireEvent.click(screen.getByRole("button", { name: /retry same request/i }));
    await flush();
    expect(screen.getByText(/RFQ outcome UNKNOWN/i)).toBeTruthy();
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);

    // Discard is two-step.
    const discard = screen.getByRole("button", {
      name: /discard unknown and continue/i,
    }) as HTMLButtonElement;
    expect(discard.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/verified the earlier RFQ/i));
    await flush();
    fireEvent.click(discard);
    await flush();
    expect(screen.queryByText(/RFQ outcome UNKNOWN/i)).toBeNull();
  });

  it("refuses to submit an RFQ when the target pair is incomplete (action-time guard)", async () => {
    // A selected instrument on a chain whose quote token is NOT advertised: the
    // RFQ target guard is the only layer, so exercise the action path directly
    // (the disabled button is bypassed) to prove it is not merely cosmetic.
    const ops: string[] = [];
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        ops.push(op);
        if (op === "get_execution_progress") {
          return {
            executionId: "ex-0",
            kind: "twap",
            state: "completed",
            chunksTotal: 1,
            chunksDone: 1,
            filledAmount: "100",
            remainingAmount: "0",
            realizedVsEstimateBps: 0,
            haltReason: null,
          } as unknown as T;
        }
        return { rfqId: "rfq-1", legs: [], bestSolver: null, state: "running" } as unknown as T;
      },
    };
    const store = createWorkspaceStore({
      manualClock: true,
      clock: () => 1_000,
      command: client,
      session: parseWorkspaceSession({
        protocol_version: 1,
        capabilities: { twap: true, rfq: true, market: true, realtime: true },
        trading_enabled: true,
        kill_switch: { enabled: false, reason: null },
        // No `native_token`: the counterparty leg cannot be resolved.
        chains: [{ id: "base", display: "Base", enabled: true }],
        session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
        server_time_ms: 1_699_999_000_000,
      }),
    });
    const reload = store.reload.bind(store);
    (store as { reload: () => void }).reload = () => {
      reload();
      queueMicrotask(() => {
        store.setConnection({
          phase: "live",
          lastFrameAtMs: 1_000,
          attempt: 0,
          nextRetryAtMs: null,
          reason: null,
        });
        store.setSelectedInstrument({ chain: "base", address: "0xselected", symbol: "TKN" });
      });
    };
    store.reload();
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <ExecutionPanel />
      </WorkspaceProvider>
    ));
    const rfqButton = screen.getByRole("button", { name: /request quotes/i }) as HTMLButtonElement;
    expect(rfqButton.disabled).toBe(true);
    // Bypass the disabled attribute and fire the handler directly.
    rfqButton.disabled = false;
    fireEvent.click(rfqButton);
    await flush();
    expect(ops).not.toContain("submit_rfq");
  });
});
