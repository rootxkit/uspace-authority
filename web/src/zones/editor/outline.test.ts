// The zone editor's geometry as the kit's drawing tool sees it: the
// outer ring and the centre the map may change, the holes and the radius
// it leaves as typed, and text it cannot read left alone (E-01 pairs).
import { describe, expect, it } from "vitest";
import type { GeometryValues } from "./model";
import { centreValues, outlineOf, outlineOfAnswer, withOuterRing } from "./outline";

const polygon = (rings: string): GeometryValues => ({ kind: "polygon", rings, centerLng: null, centerLat: null, radiusM: null });

describe("outlineOf", () => {
  it("is the outer ring's positions, the holes not drawn", () => {
    expect(outlineOf(polygon("44.70 41.70\n44.72 41.70\n44.72 41.72\n\n44.705 41.705\n44.71 41.705\n44.71 41.71"))).toEqual({
      outline: {
        kind: "polygon",
        vertices: [
          { lng: 44.7, lat: 41.7 },
          { lng: 44.72, lat: 41.7 },
          { lng: 44.72, lat: 41.72 },
        ],
      },
      editable: true,
    });
  });

  it("is not editable on the map while a line of the outer ring is not a position", () => {
    expect(outlineOf(polygon("44.70 41.70\nnot a position"))).toEqual({ outline: { kind: "polygon", vertices: [] }, editable: false });
  });

  it("is a circle's centre once both numbers are typed, and its radius", () => {
    expect(outlineOf({ kind: "circle", rings: "", centerLng: 44.85, centerLat: 41.7, radiusM: 500 }).outline).toEqual({ kind: "circle", center: { lat: 41.7, lng: 44.85 }, radiusM: 500 });
    expect(outlineOf({ kind: "circle", rings: "", centerLng: 44.85, centerLat: null, radiusM: 500 }).outline).toEqual({ kind: "circle", center: null, radiusM: 500 });
  });
});

describe("withOuterRing", () => {
  it("replaces the outer ring and keeps every hole as typed", () => {
    const next = withOuterRing("44.70 41.70\n44.72 41.70\n\n44.705 41.705\n44.71 41.705\n44.71 41.71", [
      { lng: 44.7, lat: 41.7 },
      { lng: 44.72, lat: 41.7 },
      { lng: 44.7200000123, lat: 41.7200000987 },
    ]);
    expect(next).toBe("44.7 41.7\n44.72 41.7\n44.72 41.72\n\n44.705 41.705\n44.71 41.705\n44.71 41.71");
  });

  it("writes the first ring of an empty text", () => {
    expect(withOuterRing("", [{ lng: 44.8, lat: 41.7 }])).toBe("44.8 41.7");
  });
});

describe("centreValues", () => {
  it("writes a placed centre to the click's decimals", () => {
    expect(centreValues({ lng: 44.123456789, lat: 41.987654321 })).toEqual({ centerLng: 44.123457, centerLat: 41.987654 });
  });
});

describe("outlineOfAnswer", () => {
  const ring = [
    [44.85, 41.7045],
    [44.844, 41.7],
    [44.85, 41.6955],
    [44.85, 41.7045],
  ];
  it("reads api's outline as sent", () => {
    expect(outlineOfAnswer({ outline: { type: "Polygon", coordinates: [ring] }, vertices: 3 })).toEqual({ type: "Polygon", coordinates: [ring] });
  });
  it("refuses an answer that is not a ring, rather than drawing it", () => {
    expect(outlineOfAnswer({ outline: { type: "Polygon", coordinates: [ring.slice(0, 3)] } })).toBeNull();
    expect(outlineOfAnswer({ outline: { type: "LineString", coordinates: ring } })).toBeNull();
    expect(outlineOfAnswer(undefined)).toBeNull();
  });
});
