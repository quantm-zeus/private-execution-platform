import { createContext, useContext, type JSX } from "solid-js";
import type { RealtimeFeed } from "./use-realtime";

const RealtimeFeedContext = createContext<RealtimeFeed | null>(null);

export function RealtimeFeedProvider(props: {
  feed: RealtimeFeed;
  children: JSX.Element;
}): JSX.Element {
  return <RealtimeFeedContext.Provider value={props.feed}>{props.children}</RealtimeFeedContext.Provider>;
}

/** Null when no realtime feed is mounted (tests, offline workspace). */
export function useRealtimeFeedContext(): RealtimeFeed | null {
  return useContext(RealtimeFeedContext) ?? null;
}
