import { onCleanup, onMount, type Component } from "solid-js";
import { useWorkstation } from "../state/workstation";
import { useRealtimeFeedContext } from "./feed-context";

/**
 * Routes decrypted `market` frames from the existing encrypted realtime feed
 * into the workstation store. It renders nothing and adds no transport: the
 * browser keeps exactly one encrypted WebSocket, and polling remains a
 * server-side fallback whose provenance travels in the frames themselves.
 */
export const MarketRealtimeBridge: Component = () => {
  const feed = useRealtimeFeedContext();
  const station = useWorkstation();

  onMount(() => {
    const unsubscribe = feed?.subscribe((frames) => station.applyMarketFrames(frames));
    onCleanup(() => unsubscribe?.());
  });

  return null;
};

export default MarketRealtimeBridge;
