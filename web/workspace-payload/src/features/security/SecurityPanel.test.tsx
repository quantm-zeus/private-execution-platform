import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { SecurityPanel } from "./SecurityPanel";
import { WorkspaceProvider, createWorkspaceStore } from "../../state/session";
import { parseWorkspaceSession } from "../../transport/bootstrap";
import type { CommandClient } from "../../transport/command";
import { WorkspaceError } from "../../core/types";

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function storeWith(command: CommandClient, tradingEnabled: boolean) {
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    command,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { withdraw: true, market: true },
      trading_enabled: tradingEnabled,
      kill_switch: { enabled: false, reason: null },
      chains: [{ id: "base", display: "Base", enabled: true }],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.reload();
  return store;
}

const recordingClient = (ops: string[]): CommandClient => ({
  async send<T>(op: string): Promise<T> {
    ops.push(op);
    return { request_id: "wr-1" } as unknown as T;
  },
});

describe("SecurityPanel", () => {
  afterEach(() => cleanup());

  it("fails the withdrawal surface closed while trading is disabled", async () => {
    const store = storeWith(recordingClient([]), false);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    const review = screen.getByRole("button", { name: /review withdrawal/i });
    expect((review as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getAllByText(/Trading is disabled by the global kill switch/i).length).toBeGreaterThan(0);
  });

  it("requires the exact confirmation phrase before submitting", async () => {
    const ops: string[] = [];
    const store = storeWith(recordingClient(ops), true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("Destination address"), {
      target: { value: "0x1234567890abcdef" },
    });
    fireEvent.input(screen.getByLabelText("Withdrawal amount"), { target: { value: "1.5" } });
    fireEvent.click(screen.getByRole("button", { name: /review withdrawal/i }));
    await flush();
    expect(screen.getByText("Destination")).toBeTruthy();

    const submit = screen.getByRole("button", { name: /request withdrawal/i });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(screen.getByLabelText("Withdrawal confirmation phrase"), {
      target: { value: "confirm withdrawal" },
    });
    expect((screen.getByRole("button", { name: /request withdrawal/i }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(screen.getByLabelText("Withdrawal confirmation phrase"), {
      target: { value: "CONFIRM WITHDRAWAL" },
    });
    fireEvent.click(screen.getByRole("button", { name: /request withdrawal/i }));
    await flush();
    expect(ops).toContain("request_withdrawal");
  });

  it("moves focus into the withdrawal review and back to Review on cancel", async () => {
    const store = storeWith(recordingClient([]), true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("Destination address"), {
      target: { value: "0x1234567890abcdef" },
    });
    fireEvent.input(screen.getByLabelText("Withdrawal amount"), { target: { value: "1.5" } });
    fireEvent.click(screen.getByRole("button", { name: /review withdrawal/i }));
    await flush();

    const dialog = screen.getByRole("alertdialog", { name: "Confirm withdrawal" });
    // Entering the irreversible-action review moves focus into it, so keyboard
    // and screen-reader users are not dropped onto <body>.
    expect(document.activeElement).toBe(dialog);

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await flush();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: /review withdrawal/i }));
  });

  it("refuses a second concurrent submit while the first withdrawal is in flight", async () => {
    const ops: string[] = [];
    let release!: (value: unknown) => void;
    const pending = new Promise((resolve) => {
      release = resolve;
    });
    const client: CommandClient = {
      async send<T>(op: string): Promise<T> {
        ops.push(op);
        await pending;
        return { request_id: "wr-1" } as unknown as T;
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("Destination address"), {
      target: { value: "0x1234567890abcdef" },
    });
    fireEvent.input(screen.getByLabelText("Withdrawal amount"), { target: { value: "1.5" } });
    fireEvent.click(screen.getByRole("button", { name: /review withdrawal/i }));
    fireEvent.input(screen.getByLabelText("Withdrawal confirmation phrase"), {
      target: { value: "CONFIRM WITHDRAWAL" },
    });

    const submit = () =>
      screen.getByRole("button", { name: /request withdrawal/i }) as HTMLButtonElement;
    fireEvent.click(submit());
    // The first request is still pending; the control is disabled. Solid's
    // delegated click handler ignores a disabled node, so force the control
    // enabled to exercise the *action-time* guard, not just the attribute:
    // without the guard these racing clicks would start a second write.
    expect(submit().disabled).toBe(true);
    const forceClick = () => {
      submit().disabled = false;
      fireEvent.click(submit());
    };
    forceClick();
    forceClick();
    await flush();
    expect(ops).toHaveLength(1);

    release({ request_id: "wr-1" });
    await flush();
    expect(ops).toHaveLength(1);
    expect(screen.getByText(/submitted for backend step-up confirmation/i)).toBeTruthy();
  });

  it("shows the kill-switch state and states that no signing surface exists", async () => {
    const store = storeWith(recordingClient([]), true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    expect(screen.getByText(/no generic signing/i)).toBeTruthy();
  });

  it("treats an unconfirmed withdrawal as UNKNOWN and keeps its key across a re-review", async () => {
    const keys: (string | undefined)[] = [];
    const client: CommandClient = {
      async send<T>(
        op: string,
        _payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "request_withdrawal") {
          keys.push(options?.idempotencyKey);
          throw new WorkspaceError({
            code: "network",
            message: "Command transport failed.",
            retryable: true,
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    const fill = () => {
      fireEvent.input(screen.getByLabelText("Destination address"), {
        target: { value: "0x1234567890abcdef" },
      });
      fireEvent.input(screen.getByLabelText("Withdrawal amount"), { target: { value: "1.5" } });
      fireEvent.click(screen.getByRole("button", { name: /review withdrawal/i }));
    };
    fill();
    fireEvent.input(screen.getByLabelText("Withdrawal confirmation phrase"), {
      target: { value: "CONFIRM WITHDRAWAL" },
    });
    fireEvent.click(screen.getByRole("button", { name: /request withdrawal/i }));
    await flush();
    expect(screen.getByText(/Withdrawal outcome UNKNOWN/i)).toBeTruthy();
    expect(keys).toHaveLength(1);

    // Cancel and re-review the same authorization: it is not a second, unrelated
    // withdrawal, so it must reuse the still-unresolved idempotency key.
    fireEvent.click(screen.getByRole("button", { name: /^Cancel$/ }));
    await flush();
    fill();
    fireEvent.input(screen.getByLabelText("Withdrawal confirmation phrase"), {
      target: { value: "CONFIRM WITHDRAWAL" },
    });
    fireEvent.click(screen.getByRole("button", { name: /request withdrawal/i }));
    await flush();
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBe(keys[1]);
  });

  it("blocks changed-details withdrawal while an UNKNOWN exists, until discarded", async () => {
    const keys: (string | undefined)[] = [];
    const client: CommandClient = {
      async send<T>(
        op: string,
        _payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "request_withdrawal") {
          keys.push(options?.idempotencyKey);
          throw new WorkspaceError({
            code: "network",
            message: "Command transport failed.",
            retryable: true,
          });
        }
        throw new Error(`unexpected op ${op}`);
      },
    };
    const store = storeWith(client, true);
    await flush();
    render(() => (
      <WorkspaceProvider store={store}>
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    const fill = (value: string) => {
      fireEvent.input(screen.getByLabelText("Destination address"), {
        target: { value: "0x1234567890abcdef" },
      });
      fireEvent.input(screen.getByLabelText("Withdrawal amount"), { target: { value } });
      fireEvent.click(screen.getByRole("button", { name: /review withdrawal/i }));
    };
    fill("1.5");
    fireEvent.input(screen.getByLabelText("Withdrawal confirmation phrase"), {
      target: { value: "CONFIRM WITHDRAWAL" },
    });
    fireEvent.click(screen.getByRole("button", { name: /request withdrawal/i }));
    await flush();
    expect(keys).toHaveLength(1);

    // Re-review with DIFFERENT details while the first is unresolved: this is a
    // second, unrelated authorization and must be blocked, not sent under the
    // first key.
    fireEvent.click(screen.getByRole("button", { name: /^Cancel$/ }));
    await flush();
    fill("2.5");
    fireEvent.input(screen.getByLabelText("Withdrawal confirmation phrase"), {
      target: { value: "CONFIRM WITHDRAWAL" },
    });
    expect(
      (screen.getByRole("button", { name: /request withdrawal/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(screen.getByText(/could duplicate a transfer/i)).toBeTruthy();
    expect(keys).toHaveLength(1);

    // Explicit two-step acknowledgement releases the block and rotates the key.
    fireEvent.click(screen.getByLabelText(/I verified the earlier withdrawal out-of-band/i));
    fireEvent.click(screen.getByRole("button", { name: /discard UNKNOWN and continue/i }));
    await flush();
    fireEvent.click(screen.getByRole("button", { name: /request withdrawal/i }));
    await flush();
    expect(keys).toHaveLength(2);
    expect(keys[1]).not.toBe(keys[0]);
  });

  it("keeps an unresolved withdrawal guarded when a retry is rejected determinately", async () => {
    const keys: (string | undefined)[] = [];
    let mode: "network" | "auth" = "network";
    const client: CommandClient = {
      async send<T>(
        op: string,
        _payload?: unknown,
        options?: { idempotencyKey?: string },
      ): Promise<T> {
        if (op === "request_withdrawal") {
          keys.push(options?.idempotencyKey);
          throw new WorkspaceError({
            code: mode,
            message: mode === "network" ? "Command transport failed." : "not authorized",
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
        <SecurityPanel />
      </WorkspaceProvider>
    ));
    fireEvent.input(screen.getByLabelText("Destination address"), {
      target: { value: "0x1234567890abcdef" },
    });
    fireEvent.input(screen.getByLabelText("Withdrawal amount"), { target: { value: "1.5" } });
    fireEvent.click(screen.getByRole("button", { name: /review withdrawal/i }));
    fireEvent.input(screen.getByLabelText("Withdrawal confirmation phrase"), {
      target: { value: "CONFIRM WITHDRAWAL" },
    });
    fireEvent.click(screen.getByRole("button", { name: /request withdrawal/i }));
    await flush();
    expect(screen.getByText(/Withdrawal outcome UNKNOWN/i)).toBeTruthy();

    // An auth rejection of the retry must not clear the UNKNOWN or rotate the
    // key: the first request may already have been accepted (irreversible).
    mode = "auth";
    fireEvent.click(screen.getByRole("button", { name: /request withdrawal/i }));
    await flush();
    expect(screen.getByText(/Withdrawal outcome UNKNOWN/i)).toBeTruthy();
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);
  });
});
