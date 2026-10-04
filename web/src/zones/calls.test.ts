// The publication's confirmation counts what is in force by api's clock
// (its Date header), not the browser's, and names each approved version.
import { describe, expect, it } from "vitest";
import type { ZoneVersion } from "./adapt";
import { publicationPreview, serverClockMs } from "./calls";

const zone = (identifier: string, zone_version: number, valid_from: string, valid_to: string) => ({ identifier, zone_version, valid_from, valid_to }) as unknown as ZoneVersion;

describe("serverClockMs", () => {
  it("reads api's Date header", () => {
    expect(serverClockMs("Mon, 05 Oct 2026 02:00:00 GMT")).toBe(Date.parse("2026-10-05T02:00:00Z"));
  });

  it("is null without a header, or with one that does not parse (the pair above)", () => {
    expect(serverClockMs(null)).toBeNull();
    expect(serverClockMs("")).toBeNull();
    expect(serverClockMs("yesterday")).toBeNull();
  });
});

describe("publicationPreview", () => {
  const published = [zone("TSTP001", 2, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"), zone("TSTP002", 1, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")];
  const approved = [zone("TSTP003", 1, "2026-06-01T00:00:00Z", "2027-01-01T00:00:00Z"), zone("TSTP001", 3, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")];

  it("counts in force at the instant it is given, and the count changes with it", () => {
    expect(publicationPreview(approved, published, Date.parse("2026-10-05T00:00:00Z")).inForce).toBe(3);
    expect(publicationPreview(approved, published, Date.parse("2026-03-01T00:00:00Z")).inForce).toBe(2);
    expect(publicationPreview(approved, published, Date.parse("2025-06-01T00:00:00Z")).inForce).toBe(0);
  });

  it("names each approved version, in identifier order", () => {
    expect(publicationPreview(approved, published, 0).versions).toEqual([
      { identifier: "TSTP001", version: 3 },
      { identifier: "TSTP003", version: 1 },
    ]);
  });
});
