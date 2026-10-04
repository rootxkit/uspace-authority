import { describe, expect, it } from "vitest";
import { DEFAULT_PII_PURPOSES, PII_PURPOSES_MAX, parseMapView, parsePurposes, parseZoneCountry, runtimeConfig } from "./runtime";

describe("the map's first view", () => {
  it("is read from WEB_MAP_CENTER and WEB_MAP_ZOOM", () => {
    expect(parseMapView("44.8,41.72", "9")).toEqual({ view: { center: [44.8, 41.72], zoom: 9 } });
  });

  it("is never defaulted: unset names the variable (INV-03)", () => {
    expect(runtimeConfig({})).toMatchObject({ mapView: null, mapViewProblem: "WEB_MAP_CENTER is not set" });
    expect(parseMapView("44.8,41.72", undefined)).toEqual({ problem: "WEB_MAP_ZOOM is not set" });
  });

  it("refuses a malformed or out-of-range value, and accepts the edge", () => {
    expect(parseMapView("41.72", "9")).toHaveProperty("problem");
    expect(parseMapView("181,0", "9")).toHaveProperty("problem");
    expect(parseMapView("180,90", "22")).toEqual({ view: { center: [180, 90], zoom: 22 } });
    expect(parseMapView("0,0", "23")).toHaveProperty("problem");
  });
});

describe("the registry's PII purposes", () => {
  it("unset: the default list, and the page is told it is the default (pending GCAA)", () => {
    expect(parsePurposes(undefined)).toEqual({ purposes: [...DEFAULT_PII_PURPOSES], problem: expect.stringContaining("pending GCAA") as unknown });
  });

  it("set: exactly the configured codes, without repeats (the pair above)", () => {
    expect(parsePurposes("case_review, dpo_request,case_review")).toEqual({ purposes: ["case_review", "dpo_request"], problem: null });
    expect(runtimeConfig({ WEB_PII_PURPOSES: "case_review" })).toMatchObject({ piiPurposes: ["case_review"], piiPurposesProblem: null });
  });

  it("a malformed list falls back to the default and names the variable", () => {
    expect(parsePurposes("Case Review").problem).toContain("WEB_PII_PURPOSES");
    expect(parsePurposes(",,").purposes).toEqual([...DEFAULT_PII_PURPOSES]);
  });

  it("a list past its bound is refused, and the bound itself is accepted (E-10)", () => {
    const codes = (n: number) => Array.from({ length: n }, (_, i) => `p${i}`).join(",");
    expect(parsePurposes(codes(PII_PURPOSES_MAX)).problem).toBeNull();
    expect(parsePurposes(codes(PII_PURPOSES_MAX + 1)).problem).toContain("WEB_PII_PURPOSES");
  });
});

describe("the zone editor's country", () => {
  it("is null unless configured as three upper-case letters", () => {
    expect(parseZoneCountry(undefined)).toBeNull();
    expect(parseZoneCountry("geo")).toBeNull();
    expect(parseZoneCountry("GEO")).toBe("GEO");
  });
});
