import { describe, expect, it } from "vitest";
import { createRoot } from "solid-js";
import { createCommandResource } from "./command-state";
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
});
