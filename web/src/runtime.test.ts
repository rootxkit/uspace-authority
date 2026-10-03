import { describe, expect, it } from "vitest";
import { parseMapView, runtimeConfig } from "./runtime";

describe("the map's first view", () => {
  it("is read from WEB_MAP_CENTER and WEB_MAP_ZOOM", () => {
    expect(parseMapView("44.8,41.72", "9")).toEqual({ view: { center: [44.8, 41.72], zoom: 9 } });
  });

  it("is never defaulted: unset names the variable (INV-03)", () => {
    expect(runtimeConfig({})).toEqual({ mapView: null, mapViewProblem: "WEB_MAP_CENTER is not set" });
    expect(parseMapView("44.8,41.72", undefined)).toEqual({ problem: "WEB_MAP_ZOOM is not set" });
  });

  it("refuses a malformed or out-of-range value, and accepts the edge", () => {
    expect(parseMapView("41.72", "9")).toHaveProperty("problem");
    expect(parseMapView("181,0", "9")).toHaveProperty("problem");
    expect(parseMapView("180,90", "22")).toEqual({ view: { center: [180, 90], zoom: 22 } });
    expect(parseMapView("0,0", "23")).toHaveProperty("problem");
  });
});
