// The "now" the picture header reads the last frame's age against. Both
// are readings of the browser's clock (the kit stamps lastFrameAtMs when
// a frame arrives; useNowMs ticks once a second), but the tick is up to a
// second behind a frame that arrived since it, and the header said "last
// frame -1 s ago" (live use). An age is never negative: a frame that
// arrived after the tick is read against its own arrival, 0 s. The
// server's clock is not mixed in (04 §2: an age counts on one clock).

/** The tick, or the last frame's arrival when that is later. */
export function headerNowMs(nowMs: number, lastFrameAtMs: number | null | undefined): number {
  return lastFrameAtMs === null || lastFrameAtMs === undefined || !Number.isFinite(lastFrameAtMs) ? nowMs : Math.max(nowMs, lastFrameAtMs);
}
