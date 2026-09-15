import { describe, expect, it } from "vitest";
import { createRoot } from "solid-js";
import { createCommandResource } from "./command-state";
import { workspaceError } from "../core/errors";
import type { CommandClient, CommandSendOptions } from "../transport/command";

describe("createCommandResource", () => {
  it("passes the idempotency key through to the command client", async () => {
    const seen: (CommandSendOptions | undefined)[] = [];
    const client: CommandClient = {
      async send<T>(_op: string, _payload?: unknown, options?: CommandSendOptions): Promise<T> {
        seen.push(options);
        return { ok: true } as T;
      },
    };
    await createRoot(async (dispose) => {
      const resource = createCommandResource(client, "place_limit_order", {});
      await resource.run({ amount: 5 }, { idempotencyKey: "k-1" });
      expect(seen[0]?.idempotencyKey).toBe("k-1");
      expect(resource.state().kind).toBe("ready");
      dispose();
    });
  });

  it("sends no key when none is supplied (caller must opt in per write)", async () => {
    const seen: (CommandSendOptions | undefined)[] = [];
    const client: CommandClient = {
      async send<T>(_op: string, _payload?: unknown, options?: CommandSendOptions): Promise<T> {
        seen.push(options);
        return {} as T;
      },
    };
    await createRoot(async (dispose) => {
      const resource = createCommandResource(client, "get_quote", {});
      await resource.run({});
      expect(seen[0]?.idempotencyKey).toBeUndefined();
      dispose();
    });
  });

  it("turns a validator rejection into a typed error, never a ready value", async () => {
    const client: CommandClient = {
      async send<T>(): Promise<T> {
        // The canonical snake_case document the order list cannot render.
        return { orders: [{ order_id: "o-1", status: "active" }] } as unknown as T;
      },
    };
    await createRoot(async (dispose) => {
      const resource = createCommandResource<{ readonly orders: readonly unknown[] }>(
        client,
        "get_orders",
        {
          validate: (value) => {
            const orders = (value as { orders?: unknown }).orders;
            if (!Array.isArray(orders) || (orders[0] as { orderId?: unknown })?.orderId === undefined) {
              throw workspaceError("protocol", "Malformed order list.");
            }
            return value as { readonly orders: readonly unknown[] };
          },
        },
      );
      await resource.run({});
      const state = resource.state();
      expect(state.kind).toBe("error");
      if (state.kind === "error") {
        expect(state.error.code).toBe("protocol");
      }
      dispose();
    });
  });

  it("uses the validated value for a ready state", async () => {
    const client: CommandClient = {
      async send<T>(): Promise<T> {
        return { raw: "wire" } as unknown as T;
      },
    };
    await createRoot(async (dispose) => {
      const resource = createCommandResource<string>(client, "get_quote", {
        validate: (value) => `validated:${(value as { raw: string }).raw}`,
      });
      await resource.run({});
      const state = resource.state();
      expect(state.kind).toBe("ready");
      if (state.kind === "ready") {
        expect(state.value).toBe("validated:wire");
      }
      dispose();
    });
  });
});
