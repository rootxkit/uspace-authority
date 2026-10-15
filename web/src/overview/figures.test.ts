// The overview's figures: a queue page with more behind it says so (and
// one without does not), and the sources are counted by their state.
import { describe, expect, it } from "vitest";
import { queueCount, sourceSummary } from "./figures";

describe("queueCount", () => {
  it("a last page is the whole count", () => {
    expect(queueCount([1, 2, 3], undefined)).toEqual({ count: 3, more: false });
    expect(queueCount([], undefined)).toEqual({ count: 0, more: false });
  });

  it("a page with a next cursor is a lower bound (the pair above)", () => {
    expect(queueCount([1, 2], "cursor-2")).toEqual({ count: 2, more: true });
  });
});

describe("sourceSummary", () => {
  it("every source healthy: nothing needs attention", () => {
    expect(sourceSummary([{ state: "healthy" }, { state: "healthy" }])).toEqual({ total: 2, healthy: 2, disabled: 0, attention: 0 });
  });

  it("a disabled source is not a problem; every other state is counted as one (the pair above)", () => {
    const states = ["healthy", "disabled", "stale", "lagging", "unreachable", "never_heard"] as const;
    expect(sourceSummary(states.map((state) => ({ state })))).toEqual({ total: 6, healthy: 1, disabled: 1, attention: 4 });
  });

  it("no source reported is a total of zero, not a healthy picture", () => {
    expect(sourceSummary([])).toEqual({ total: 0, healthy: 0, disabled: 0, attention: 0 });
  });
});
