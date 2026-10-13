// The header's last-frame age (live use: "last frame -1 s ago"), through
// the kit's FeedStatusBar as the page renders it, and its twin: an older
// frame still ages on the tick.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { I18nProvider } from "@rootxkit/uspace-ui/i18n";
import { FeedStatusBar, type FeedStatusInput } from "@rootxkit/uspace-ui/status";
import { catalogues } from "../i18n/catalogues";
import { headerNowMs } from "./feedAge";

const TICK_MS = 1_760_000_000_000;

function status(lastFrameAtMs: number | null): FeedStatusInput {
  return { connection: "live", sinceMs: TICK_MS - 60_000, droppedFrames: 0, degraded: [], staleAfterS: 15, liveMaxAgeS: 5, policyVersion: "1", serverTs: null, lastFrameAtMs };
}

function lastFrameText(lastFrameAtMs: number | null, nowMs: number): string {
  const html = renderToStaticMarkup(
    createElement(I18nProvider, { lang: "en", catalogues }, createElement(FeedStatusBar, { status: status(lastFrameAtMs), nowMs })),
  );
  const m = /data-part="last-frame">([^<]*)</.exec(html);
  return m?.[1] ?? "";
}

describe("the picture header's last-frame age", () => {
  it("is 0 s, never negative, for a frame that arrived after the tick", () => {
    const arrived = TICK_MS + 700;
    expect(lastFrameText(arrived, TICK_MS)).toBe("last frame -1 s ago");
    expect(lastFrameText(arrived, headerNowMs(TICK_MS, arrived))).toBe("last frame 0 s ago");
  });

  it("climbs on the tick for an older frame", () => {
    const arrived = TICK_MS - 12_000;
    expect(headerNowMs(TICK_MS, arrived)).toBe(TICK_MS);
    expect(lastFrameText(arrived, headerNowMs(TICK_MS, arrived))).toBe("last frame 12 s ago");
  });

  it("is the tick when no frame has arrived", () => {
    expect(headerNowMs(TICK_MS, null)).toBe(TICK_MS);
    expect(headerNowMs(TICK_MS, undefined)).toBe(TICK_MS);
    expect(headerNowMs(TICK_MS, Number.NaN)).toBe(TICK_MS);
  });
});
