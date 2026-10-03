import { describe, expect, it } from "vitest";
import { adaptZone, localText, type ZoneVersion } from "./adapt";

function zone(geometry: Record<string, unknown>, type = "PROHIBITED"): ZoneVersion {
  return {
    dataset: "zones",
    identifier: "TSTP001",
    zone_version: 2,
    state: "published",
    type: type as ZoneVersion["type"],
    country: "GEO",
    // ED318Feature is a raw JSON object in the API types (x-go-type json.RawMessage).
    feature: {
      type: "Feature",
      geometry,
      properties: { identifier: "TSTP001", type, name: [{ lang: "ka-GE", text: "ზონა" }, { lang: "en-GB", text: "Zone" }] },
    } as unknown as ZoneVersion["feature"],
    valid_from: "2026-01-01T00:00:00Z",
    valid_to: "2027-01-01T00:00:00Z",
    extensions: [],
    published_version: 7,
    created_at: "2026-01-01T00:00:00Z",
    created_by: "u",
  };
}

const polygon = {
  type: "Polygon",
  coordinates: [
    [
      [44, 41],
      [45, 41],
      [45, 42],
      [44, 41],
    ],
  ],
  layer: { lower: 0, lowerReference: "AGL", upper: 120, upperReference: "AGL", uom: "m" },
};

describe("adaptZone", () => {
  it("draws a polygon as published, with its limits in metres", () => {
    const a = adaptZone(zone(polygon), "en");
    expect(a.drawn).toBe(true);
    if (!a.drawn) return;
    expect(a.view).toMatchObject({ identifier: "TSTP001", name: "Zone", type: "PROHIBITED", lowerLimitM: 0, upperLimitM: 120, upperRef: "AGL", version: "7" });
    expect(a.view.geometry).toEqual({ type: "Polygon", coordinates: polygon.coordinates });
  });

  it("lists a circle as not drawn, never approximates it", () => {
    expect(adaptZone(zone({ type: "Point", coordinates: [44, 41], extent: { subType: "Circle", radius: 500 } }), "en")).toEqual({
      drawn: false,
      identifier: "TSTP001",
      reason: "geometry",
    });
  });

  it("never converts feet: a limit in feet is not a limit in metres", () => {
    const a = adaptZone(zone({ ...polygon, layer: { ...polygon.layer, uom: "ft", upper: 400 } }), "en");
    expect(a.drawn && a.view.upperLimitM).toBeNull();
  });

  it("refuses a type the kit cannot draw, and says so", () => {
    expect(adaptZone(zone(polygon, "SOMETHING"), "en")).toMatchObject({ drawn: false, reason: "type" });
  });

  it("chooses the viewer's language, else the first text", () => {
    const names = [
      { lang: "ka-GE", text: "ზონა" },
      { lang: "en-GB", text: "Zone" },
    ];
    expect(localText(names, "ka")).toBe("ზონა");
    expect(localText(names, "en")).toBe("Zone");
    expect(localText([{ lang: "de-DE", text: "Zone DE" }], "en")).toBe("Zone DE");
    expect(localText(undefined, "en")).toBeNull();
  });
});
