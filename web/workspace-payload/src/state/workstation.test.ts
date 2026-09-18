import { describe, expect, it } from "vitest";
import { createRoot } from "solid-js";
import { createWorkstationStore, type DockTab } from "./workstation";
import { createWorkspaceStore } from "./session";
import { parseWorkspaceSession } from "../transport/bootstrap";
import type { CommandClient } from "../transport/command";

/** Compile-time proof the union no longer admits `trades`. */
type AssertFalse<T> = T extends true ? never : true;
type HasTrades = "trades" extends DockTab ? true : false;
const _tradesRemoved: AssertFalse<HasTrades> = true;

function workspace() {
  const command: CommandClient = {
    async send<T>(op: string): Promise<T> {
      if (op === "set_realtime_target") return { accepted: true } as unknown as T;
      throw new Error(`unexpected op ${op}`);
    },
  };
  const store = createWorkspaceStore({
    manualClock: true,
    clock: () => 1_000,
    session: parseWorkspaceSession({
      protocol_version: 1,
      capabilities: { market: true, realtime: true, token_intelligence: true },
      trading_enabled: false,
      kill_switch: { enabled: false, reason: null },
      chains: [],
      session: { key_id: "kid-1", expires_at_ms: 1_700_000_000_000 },
      server_time_ms: 1_699_999_000_000,
    }),
  });
  store.setCommand(command);
  store.reload();
  return store;
}

describe("DockTab union + dock sizing state", () => {
  it("has exactly the five V2 members and no `trades`", () => {
    expect(_tradesRemoved).toBe(true);
    createRoot((dispose) => {
      const station = createWorkstationStore(workspace());
      const members: DockTab[] = ["positions", "orders", "activity", "holders", "about"];
      for (const member of members) {
        station.setDockTab(member);
        expect(station.dockTab()).toBe(member);
      }
      dispose();
    });
  });

  it("keeps dock height and expansion memory-only", () => {
    createRoot((dispose) => {
      const station = createWorkstationStore(workspace());
      expect(station.dockHeight()).toBeNull();
      expect(station.dockExpanded()).toBe(false);
      station.setDockHeight(320);
      expect(station.dockHeight()).toBe(320);
      station.toggleDockExpanded();
      expect(station.dockExpanded()).toBe(true);
      station.setDockHeight(null);
      expect(station.dockHeight()).toBeNull();
      dispose();
    });
  });

  it("derives the exact intel key and refuses an unverified chain", () => {
    createRoot((dispose) => {
      const ws = workspace();
      const station = createWorkstationStore(ws);
      expect(station.intelKey()).toBeNull();
      ws.setSelectedInstrument({ chain: "solana", address: "TokenA", symbol: "AAA" });
      expect(station.intelKey()).toEqual({
        chain: "solana",
        networkId: 1399811149,
        address: "TokenA",
      });
      ws.setSelectedInstrument({ chain: "monad", address: "0xabc", symbol: "MON" });
      expect(station.intelKey()).toBeNull();
      dispose();
    });
  });
});
