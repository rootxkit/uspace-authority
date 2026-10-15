// The overview's figures: a queue page with more behind it says so (and
// one without does not), the sources are counted by their state, and
// api's counts list the statuses it counted in the contract's order.
import { describe, expect, it } from "vitest";
import { breakdown, CERTIFICATE_STATUSES, countSummary, queueCount, REGISTRY_STATUSES, sourceSummary, ZONE_STATES } from "./figures";

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

describe("breakdown and countSummary", () => {
  it("lists the statuses api counted, in the contract's order", () => {
    expect(breakdown({ expired: 2, active: 5, suspended: 0 }, REGISTRY_STATUSES)).toEqual([
      { status: "active", count: 5 },
      { status: "expired", count: 2 },
    ]);
    expect(countSummary({ active: 5, suspended: 0, revoked: 1, expired: 2, total: 8 }, REGISTRY_STATUSES, "2026-10-15T08:00:00Z")).toEqual({
      count: 8,
      more: false,
      items: [
        { status: "active", count: 5 },
        { status: "revoked", count: 1 },
        { status: "expired", count: 2 },
      ],
      asOf: "2026-10-15T08:00:00Z",
    });
  });

  it("a summary of zeros is a counted zero with nothing listed (the pair above)", () => {
    const s = countSummary({ as_of: "x", draft: 0, approved: 0, published: 0, superseded: 0, total: 0 }, ZONE_STATES, "x");
    expect(s).toEqual({ count: 0, more: false, items: [], asOf: "x" });
  });

  it("a member that is not a count, or a status outside the order, is not listed", () => {
    expect(countSummary({ as_of: "x", issued: 1, unknown: 9, total: 1 }, CERTIFICATE_STATUSES, "x").items).toEqual([{ status: "issued", count: 1 }]);
  });
});
