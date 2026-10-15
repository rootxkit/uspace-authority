"use client";

// The top bar's live/stale pill. Only a page with the picture feed open
// (the overview, the live picture) has something true to say, so the
// page reports its feed to the shell and the shell draws the pill; every
// other page shows none rather than one that says nothing. "Stale" is
// the server's statement: an age past the stale_after_s its status frame
// sent, never a threshold of the console's (INV-03).
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import type { LiveFeed } from "@rootxkit/uspace-ui/live";
import type { FeedPillState } from "@rootxkit/uspace-ui/ui";

export interface ShellFeed {
  state: FeedPillState;
  /** Seconds since the last frame; null before the first. */
  ageS: number | null;
}

/** The pill's state for a feed at `nowMs`, from what the feed says. */
export function feedPill(feed: Pick<LiveFeed, "connection" | "lastFrameAtMs" | "staleAfterS">, nowMs: number): ShellFeed {
  const ageS = feed.lastFrameAtMs === null ? null : Math.max(0, (nowMs - feed.lastFrameAtMs) / 1000);
  if (feed.connection !== "live") return { state: feed.connection, ageS };
  const stale = feed.staleAfterS !== null && ageS !== null && ageS > feed.staleAfterS;
  return { state: stale ? "stale" : "live", ageS };
}

const SetterContext = createContext<((f: ShellFeed | null) => void) | null>(null);
const FeedContext = createContext<ShellFeed | null>(null);

export function ShellFeedProvider({ children }: { children: ReactNode }) {
  const [feed, setFeed] = useState<ShellFeed | null>(null);
  return (
    <SetterContext.Provider value={setFeed}>
      <FeedContext.Provider value={feed}>{children}</FeedContext.Provider>
    </SetterContext.Provider>
  );
}

/** The feed the current page reported; null on a page without one. */
export function useShellFeed(): ShellFeed | null {
  return useContext(FeedContext);
}

/** Reports the page's feed to the top bar while the page is shown. */
export function useReportFeed(feed: Pick<LiveFeed, "connection" | "lastFrameAtMs" | "staleAfterS">, nowMs: number): void {
  const set = useContext(SetterContext);
  const { state, ageS } = feedPill(feed, nowMs);
  // Whole seconds: the pill says "updated 3 s ago", so a finer age would only re-render the shell.
  const shownAgeS = ageS === null ? null : Math.floor(ageS);
  useEffect(() => {
    set?.({ state, ageS: shownAgeS });
  }, [set, state, shownAgeS]);
  useEffect(() => () => set?.(null), [set]);
}
