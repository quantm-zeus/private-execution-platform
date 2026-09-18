import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { WalletLimitsPanel } from "./WalletLimitsPanel";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import type { CommandClient } from "../../transport/command";
import { WorkspaceError } from "../../core/types";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const LIMITS = {
  wallet_ref: "0xwallet",
  max_trade_usd: 5_000,
  hourly_turnover_usd: 20_000,
  daily_turnover_usd: 100_000,
  max_buy_tax_bps: 500,
  max_sell_tax_bps: 400,
  max_price_impact_bps: 150,
  max_slippage_bps: 100,
  allowed_chains: ["base"],
  allowed_routers: ["okx"],
  allowed_programs: ["0xrouter"],
  source_age_ms: 1_200,
  slot: 7,
};

interface Recorded {
  readonly op: string;
  readonly payload: unknown;
  readonly key?: string;
}

async function storeWith(
  command: CommandClient,
  capabilities: Record<string, boolean> = { wallet_limits: true, market: true },
  tradingEnabled = true,
) {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities,
      trading_enabled: tradingEnabled,
      kill_switch: { enabled: false, reason: null },
      chains: [{ id: "base", display: "Base", enabled: true, native_token: "USDC" }],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.reload();
  await flush();
  return store;
}

function recordingClient(
  ops: Recorded[],
  onWrite?: (op: string) => void,
): CommandClient {
  return {
    async send<T>(op: string, payload?: unknown, options?: { idempotencyKey?: string }): Promise<T> {
      ops.push({ op, payload, key: options?.idempotencyKey });
      if (op === "get_wallet_limits") return LIMITS as unknown as T;
      if (op === "set_wallet_limits") {
        onWrite?.(op);
        return { ok: true } as unknown as T;
      }
      throw new Error(`unexpected op ${op}`);
    },
  };
}

function renderPanel(store: ReturnType<typeof createWorkspaceStore>) {
  return render(() => (
    <WorkspaceProvider store={store}>
      <WalletLimitsPanel />
    </WorkspaceProvider>
  ));
}

describe("WalletLimitsPanel", () => {
  afterEach(() => cleanup());

  it("fails closed and sends no command when the capability is absent", async () => {
    const ops: Recorded[] = [];
    const store = await storeWith(recordingClient(ops), { market: true });
    renderPanel(store);
    await flush();
    expect(ops).toHaveLength(0);
    expect(screen.getByText("Not available on this deployment")).toBeTruthy();
  });

  it("renders the authoritative limits and starts with an empty diff", async () => {
    const ops: Recorded[] = [];
    const store = await storeWith(recordingClient(ops));
    renderPanel(store);
    await flush();
    expect((screen.getByTestId("limit-maxTradeUsd") as HTMLInputElement).value).toBe("5000");
    expect((screen.getByTestId("limit-maxSlippageBps") as HTMLInputElement).value).toBe("100");
    expect((screen.getByLabelText("Allow chain base") as HTMLInputElement).checked).toBe(true);
    expect(screen.getByText("No changes yet.")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("saves a tightening change without a confirmation phrase", async () => {
    const ops: Recorded[] = [];
    const store = await storeWith(recordingClient(ops));
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "1000" } });
    const save = screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement;
    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    await flush();
    const write = ops.find((entry) => entry.op === "set_wallet_limits");
    expect(write?.payload).toMatchObject({
      max_trade_usd: 1_000,
      allowed_chains: ["base"],
      allowed_routers: ["okx"],
      allowed_programs: ["0xrouter"],
    });
    expect(write?.key).toMatch(/^wallet_limits-/);
  });

  it("requires the exact phrase to relax a limit", async () => {
    const ops: Recorded[] = [];
    const store = await storeWith(recordingClient(ops));
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "9000" } });
    const save = () => screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement;
    expect(save().disabled).toBe(true);
    expect(screen.getByText(/relaxes a safety limit/i)).toBeTruthy();

    fireEvent.input(screen.getByLabelText("Limit change confirmation phrase"), {
      target: { value: "confirm limit change" },
    });
    expect(save().disabled).toBe(true);
    fireEvent.input(screen.getByLabelText("Limit change confirmation phrase"), {
      target: { value: "CONFIRM LIMIT CHANGE" },
    });
    expect(save().disabled).toBe(false);
    fireEvent.click(save());
    await flush();
    expect(ops.find((entry) => entry.op === "set_wallet_limits")?.payload).toMatchObject({
      max_trade_usd: 9_000,
    });
  });

  it("treats adding a newly permitted program as a relaxation", async () => {
    const ops: Recorded[] = [];
    const store = await storeWith(recordingClient(ops));
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByLabelText("Allowed programs"), {
      target: { value: "0xrouter, 0xnew" },
    });
    expect(screen.getByText(/relaxes a safety limit/i)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(ops.some((entry) => entry.op === "set_wallet_limits")).toBe(false);
  });

  it("rejects a malformed cap and never saves it as an implicit 'no cap'", async () => {
    const ops: Recorded[] = [];
    const store = await storeWith(recordingClient(ops));
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "abc" } });
    expect(screen.getByText(/plain decimal number/i)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement).disabled,
    ).toBe(true);
    // A non-decimal literal that Number() would silently reinterpret (0x100 = 256)
    // must be a field error, never a different cap.
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "0x100" } });
    expect(screen.getByText(/plain decimal number/i)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(ops.some((entry) => entry.op === "set_wallet_limits")).toBe(false);
  });

  it("renders an ambiguous write as UNKNOWN and reuses the key on an idempotent retry", async () => {
    const ops: Recorded[] = [];
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown, options?: { idempotencyKey?: string }): Promise<T> {
        ops.push({ op, payload, key: options?.idempotencyKey });
        if (op === "get_wallet_limits") return LIMITS as unknown as T;
        throw new WorkspaceError({
          code: "network",
          message: "Command transport failed.",
          retryable: true,
        });
      },
    };
    const store = await storeWith(client);
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "1000" } });
    fireEvent.click(screen.getByRole("button", { name: "Save limits" }));
    await flush();
    expect(screen.getByText(/Limit-change outcome UNKNOWN/i)).toBeTruthy();

    // Retrying the same change is idempotent: the key is reused.
    fireEvent.click(screen.getByRole("button", { name: "Save limits" }));
    await flush();
    const writes = ops.filter((entry) => entry.op === "set_wallet_limits");
    expect(writes).toHaveLength(2);
    expect(writes[1].key).toBe(writes[0].key);
  });

  it("blocks a different change while an UNKNOWN exists until it is discarded", async () => {
    const ops: Recorded[] = [];
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown, options?: { idempotencyKey?: string }): Promise<T> {
        ops.push({ op, payload, key: options?.idempotencyKey });
        if (op === "get_wallet_limits") return LIMITS as unknown as T;
        throw new WorkspaceError({
          code: "network",
          message: "Command transport failed.",
          retryable: true,
        });
      },
    };
    const store = await storeWith(client);
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "1000" } });
    fireEvent.click(screen.getByRole("button", { name: "Save limits" }));
    await flush();
    expect(screen.getByText(/Limit-change outcome UNKNOWN/i)).toBeTruthy();

    // A different policy under the same unresolved key is refused.
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "2000" } });
    expect(screen.getByText(/may already have been applied/i)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement).disabled,
    ).toBe(true);

    fireEvent.click(screen.getByLabelText(/I verified the earlier limit change out-of-band/i));
    fireEvent.click(screen.getByRole("button", { name: /Discard UNKNOWN and continue/i }));
    await flush();
    const save = screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement;
    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    await flush();
    const writes = ops.filter((entry) => entry.op === "set_wallet_limits");
    expect(writes).toHaveLength(2);
    expect(writes[1].key).not.toBe(writes[0].key);
    expect(writes[1].payload).toMatchObject({ max_trade_usd: 2_000 });
  });

  it("keeps an UNKNOWN guarded when a retry is rejected determinately", async () => {
    const ops: Recorded[] = [];
    let mode: "network" | "auth" = "network";
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown, options?: { idempotencyKey?: string }): Promise<T> {
        ops.push({ op, payload, key: options?.idempotencyKey });
        if (op === "get_wallet_limits") return LIMITS as unknown as T;
        throw new WorkspaceError({
          code: mode,
          message: mode === "network" ? "Command transport failed." : "not authorized",
          retryable: mode === "network",
        });
      },
    };
    const store = await storeWith(client);
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "1000" } });
    fireEvent.click(screen.getByRole("button", { name: "Save limits" }));
    await flush();
    expect(screen.getByText(/Limit-change outcome UNKNOWN/i)).toBeTruthy();

    mode = "auth";
    fireEvent.click(screen.getByRole("button", { name: "Save limits" }));
    await flush();
    expect(screen.getByText(/Limit-change outcome UNKNOWN/i)).toBeTruthy();
    const writes = ops.filter((entry) => entry.op === "set_wallet_limits");
    expect(writes).toHaveLength(2);
    expect(writes[1].key).toBe(writes[0].key);
  });

  it("fails closed on a malformed backend response instead of guessing", async () => {
    const ops: Recorded[] = [];
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        ops.push({ op, payload: undefined });
        if (op === "get_wallet_limits") {
          // Missing restriction lists: must never be rendered as "unrestricted".
          return { max_trade_usd: 100, source_age_ms: 0 } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = await storeWith(client);
    renderPanel(store);
    await flush();
    expect(screen.getByText(/Malformed wallet-limits response/i)).toBeTruthy();
    expect(screen.queryByTestId("limit-maxTradeUsd")).toBeNull();
    expect(ops.some((entry) => entry.op === "set_wallet_limits")).toBe(false);
  });

  it("keeps the write fail-closed while trading is disabled", async () => {
    const ops: Recorded[] = [];
    const store = await storeWith(recordingClient(ops), { wallet_limits: true, market: true }, false);
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "1000" } });
    expect(
      (screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(screen.getByText(/Trading is disabled by the global kill switch/i)).toBeTruthy();
  });

  it("restores the authoritative values on Reset", async () => {
    const ops: Recorded[] = [];
    const store = await storeWith(recordingClient(ops));
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "1000" } });
    expect((screen.getByTestId("limit-maxTradeUsd") as HTMLInputElement).value).toBe("1000");
    fireEvent.click(screen.getByRole("button", { name: "Reset" }));
    expect((screen.getByTestId("limit-maxTradeUsd") as HTMLInputElement).value).toBe("5000");
    expect(screen.getByText("No changes yet.")).toBeTruthy();
  });

  it("refuses the write at action time when the session expires after render", async () => {
    const ops: Recorded[] = [];
    let now = 1_000;
    const store = createWorkspaceStore({
      manualClock: true,
      clock: () => now,
      command: recordingClient(ops),
      session: parseWorkspaceSession({
        protocol_version: 1,
        capabilities: { wallet_limits: true, market: true },
        trading_enabled: true,
        kill_switch: { enabled: false, reason: null },
        chains: [{ id: "base", display: "Base", enabled: true, native_token: "USDC" }],
        // 1s session so it can lapse between render and submit.
        session: { key_id: "kid-1", expires_at_ms: 1_700_000_001_000 },
        server_time_ms: 1_699_999_000_000,
      }),
    });
    store.reload();
    await flush();
    renderPanel(store);
    await flush();

    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "1000" } });
    const save = screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement;
    expect(save.disabled).toBe(false);

    // The session lapses. The memo does not necessarily re-run, so force the
    // click; the action-time gate must still refuse to send the write.
    now = 1_700_000_010_000;
    save.disabled = false;
    fireEvent.click(save);
    await flush();
    expect(ops.some((entry) => entry.op === "set_wallet_limits")).toBe(false);
    expect(screen.getByText(/expired — re-authenticate/i)).toBeTruthy();
  });

  it("verifies the change against the authoritative re-read", async () => {
    let current: Record<string, unknown> = { ...LIMITS };
    const client: CommandClient = {
      async send<T>(op: string, payload?: unknown): Promise<T> {
        if (op === "get_wallet_limits") return current as unknown as T;
        if (op === "set_wallet_limits") {
          const next = payload as { max_trade_usd: number | null };
          current = { ...current, max_trade_usd: next.max_trade_usd };
          return { ok: true } as unknown as T;
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = await storeWith(client);
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "1000" } });
    fireEvent.click(screen.getByRole("button", { name: "Save limits" }));
    await flush();
    await flush();
    expect(screen.getByText(/verified against the authoritative policy/i)).toBeTruthy();
    expect((screen.getByTestId("limit-maxTradeUsd") as HTMLInputElement).value).toBe("1000");
  });

  it("reports a change the backend did not apply instead of a false success", async () => {
    const ops: Recorded[] = [];
    // The write succeeds but the authoritative read still reports the old policy.
    const store = await storeWith(recordingClient(ops));
    renderPanel(store);
    await flush();
    fireEvent.input(screen.getByTestId("limit-maxTradeUsd"), { target: { value: "1000" } });
    fireEvent.click(screen.getByRole("button", { name: "Save limits" }));
    await flush();
    await flush();
    expect(screen.getByText(/was NOT applied/i)).toBeTruthy();
    expect((screen.getByTestId("limit-maxTradeUsd") as HTMLInputElement).value).toBe("5000");
  });
});
