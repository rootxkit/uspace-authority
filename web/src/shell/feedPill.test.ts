// The top bar's pill says what the feed says: live while frames arrive
// within the server's stale_after_s, stale past it, and never stale
// without a threshold from the server (INV-03).
import { describe, expect, it } from "vitest";
import { feedPill } from "./feedPill";

const NOW = 1_000_000;

describe("feedPill", () => {
  it("a live feed with a recent frame is live, with its age", () => {
    expect(feedPill({ connection: "live", lastFrameAtMs: NOW - 2_000, staleAfterS: 5 }, NOW)).toEqual({ state: "live", ageS: 2 });
  });

  it("a live feed whose last frame is older than stale_after_s is stale (the pair above)", () => {
    expect(feedPill({ connection: "live", lastFrameAtMs: NOW - 6_000, staleAfterS: 5 }, NOW)).toEqual({ state: "stale", ageS: 6 });
  });

  it("without the server's threshold a quiet feed stays live and its age climbs", () => {
    expect(feedPill({ connection: "live", lastFrameAtMs: NOW - 60_000, staleAfterS: null }, NOW)).toEqual({ state: "live", ageS: 60 });
  });

  it("connecting and down are said as they are; no frame yet is no age", () => {
    expect(feedPill({ connection: "connecting", lastFrameAtMs: null, staleAfterS: null }, NOW)).toEqual({ state: "connecting", ageS: null });
    expect(feedPill({ connection: "down", lastFrameAtMs: NOW - 1_000, staleAfterS: 5 }, NOW)).toEqual({ state: "down", ageS: 1 });
  });

  it("a frame stamped after the tick is no negative age", () => {
    expect(feedPill({ connection: "live", lastFrameAtMs: NOW + 500, staleAfterS: 5 }, NOW)).toEqual({ state: "live", ageS: 0 });
  });
});
