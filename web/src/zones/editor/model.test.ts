// The editor's values become the ED-318 feature api is sent, member by
// member, and an existing feature reads back into the same values. The
// bodies built here are committed as test/fixtures/zone-editor/*.json,
// which internal/zonesvc/webeditor_test.go runs through the zone
// service's own validation (uspace-core ed318.Parse and the period and
// designation checks), so a member name the editor gets wrong fails in
// Go, not in production (E-03). UPDATE_FIXTURES=1 rewrites them.
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { diff, DIFF_MAX } from "../diff";
import {
  EditorProblem,
  emptyAuthority,
  emptyValues,
  extensionRefs,
  fromFeature,
  parseRings,
  ringsText,
  toFeature,
  type ZoneEditorValues,
} from "./model";
import { designationOf, emptyDesignation } from "./designation";

const fixtures = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../test/fixtures/zone-editor");

function pinned(name: string, body: unknown): void {
  const file = path.join(fixtures, name);
  const text = `${JSON.stringify(body, null, 2)}\n`;
  if (process.env["UPDATE_FIXTURES"] === "1") writeFileSync(file, text);
  expect(readFileSync(file, "utf8"), `${name} is stale: run UPDATE_FIXTURES=1 pnpm vitest run src/zones/editor`).toBe(text);
}

/** Every ED-318 member the editor has a field for, filled in. */
function full(): ZoneEditorValues {
  const v = emptyValues({ country: "GEO" });
  return {
    ...v,
    identifier: "TSTE001",
    name: [
      { text: "Test editor zone", lang: "en-GB" },
      { text: "სატესტო ზონა", lang: "ka-GE" },
    ],
    type: "REQ_AUTHORIZATION",
    variant: "COMMON",
    restrictionConditions: "Permission of the test authority",
    region: 1,
    reason: ["NATURE", "AIR_TRAFFIC"],
    otherReasonInfo: [{ text: "A test reserve", lang: "en-GB" }],
    regulationExemption: "NO",
    message: [{ text: "Ask before flying", lang: "en-GB" }],
    extendedProperties: '{"note": "test"}',
    limitedApplicability: [
      {
        startDateTime: "2026-10-01T00:00:00Z",
        endDateTime: "2027-09-30T23:59:59Z",
        schedule: [
          { day: ["MON", "TUE"], start: "event", startTime: "", startEvent: "SR", end: "event", endTime: "", endEvent: "SS" },
          { day: ["SAT"], start: "time", startTime: "08:00:00Z", startEvent: "", end: "time", endTime: "16:00:00Z", endEvent: "" },
        ],
      },
    ],
    zoneAuthority: [
      {
        ...emptyAuthority("en-GB"),
        name: "Test authority",
        service: "Zone office",
        contactName: "Duty officer",
        siteURL: "https://authority.test/zones",
        email: "zones@authority.test",
        phone: "+995000000000",
        purpose: "AUTHORIZATION",
        intervalBefore: "P2D",
      },
    ],
    dataSource: { creationDateTime: "2026-09-01T00:00:00Z", updateDateTime: "2026-09-02T00:00:00Z", originatorText: "Test authority", originatorLang: "en-GB" },
    geometry: { kind: "polygon", rings: "44.76 41.69\n44.80 41.69\n44.80 41.73\n44.76 41.73", centerLng: null, centerLat: null, radiusM: null },
    layer: { lower: 0, lowerReference: "AGL", upper: 120, upperReference: "AGL", uom: "m" },
  };
}

const PERIOD = { valid_from: "2026-10-01T00:00:00Z", valid_to: "2027-10-01T00:00:00Z" };

describe("toFeature", () => {
  it("a polygon with every member, by its ED-318 name, the ring closed", () => {
    const f = toFeature(full());
    expect(f["type"]).toBe("Feature");
    const g = f["geometry"] as Record<string, unknown>;
    expect(g).toEqual({
      type: "Polygon",
      coordinates: [
        [
          [44.76, 41.69],
          [44.8, 41.69],
          [44.8, 41.73],
          [44.76, 41.73],
          [44.76, 41.69],
        ],
      ],
      layer: { upper: 120, upperReference: "AGL", lower: 0, lowerReference: "AGL", uom: "m" },
    });
    const p = f["properties"] as Record<string, unknown>;
    expect(Object.keys(p).sort()).toEqual(
      [
        "identifier",
        "country",
        "name",
        "type",
        "variant",
        "restrictionConditions",
        "region",
        "reason",
        "otherReasonInfo",
        "regulationExemption",
        "message",
        "extendedProperties",
        "limitedApplicability",
        "zoneAuthority",
        "dataSource",
      ].sort(),
    );
    // Reasons in the enumeration's order, not the order ticked.
    expect(p["reason"]).toEqual(["AIR_TRAFFIC", "NATURE"]);
    expect(p["limitedApplicability"]).toEqual([
      {
        startDateTime: "2026-10-01T00:00:00Z",
        endDateTime: "2027-09-30T23:59:59Z",
        schedule: [
          { day: ["MON", "TUE"], startEvent: "SR", endEvent: "SS" },
          { day: ["SAT"], startTime: "08:00:00Z", endTime: "16:00:00Z" },
        ],
      },
    ]);
    pinned("polygon-full.json", { feature: f, ...PERIOD });
  });

  it("a circle is its centre and radius, never a polygon (Z-11)", () => {
    const v: ZoneEditorValues = {
      ...full(),
      identifier: "TSTE002",
      type: "PROHIBITED",
      reason: [],
      otherReasonInfo: [],
      limitedApplicability: [],
      extendedProperties: "",
      dataSource: { creationDateTime: null, updateDateTime: null, originatorText: "", originatorLang: "en-GB" },
      zoneAuthority: [{ ...emptyAuthority("en-GB"), name: "Test authority", purpose: "INFORMATION" }],
      geometry: { kind: "circle", rings: "", centerLng: 44.85, centerLat: 41.7, radiusM: 500 },
      layer: { lower: 0, lowerReference: "AGL", upper: 60, upperReference: "AGL", uom: "m" },
    };
    const f = toFeature(v);
    expect(f["geometry"]).toEqual({
      type: "Point",
      coordinates: [44.85, 41.7],
      extent: { subType: "Circle", radius: 500 },
      layer: { upper: 60, upperReference: "AGL", lower: 0, lowerReference: "AGL", uom: "m" },
    });
    pinned("circle.json", { feature: f, ...PERIOD });
  });

  it("an empty member is left out, never sent empty (the pair of the full feature)", () => {
    const v = { ...full(), restrictionConditions: " ", region: null, otherReasonInfo: [{ text: "", lang: "en-GB" }], message: [], extendedProperties: "" };
    const p = toFeature(v)["properties"] as Record<string, unknown>;
    expect(p).not.toHaveProperty("restrictionConditions");
    expect(p).not.toHaveProperty("region");
    expect(p).not.toHaveProperty("otherReasonInfo");
    expect(p).not.toHaveProperty("message");
    expect(p).not.toHaveProperty("extendedProperties");
  });

  it("names the field of a geometry or an extension it cannot build", () => {
    const at = (v: ZoneEditorValues) => {
      try {
        toFeature(v);
        return null;
      } catch (e) {
        return e instanceof EditorProblem ? e.field : String(e);
      }
    };
    expect(at({ ...full(), geometry: { ...full().geometry, rings: "44.76 41.69\n44.80" } })).toBe("geometry.rings");
    expect(at({ ...full(), geometry: { kind: "circle", rings: "", centerLng: 44.8, centerLat: null, radiusM: 5 } })).toBe("geometry.center");
    expect(at({ ...full(), geometry: { kind: "circle", rings: "", centerLng: 44.8, centerLat: 41.7, radiusM: 0 } })).toBe("geometry.radiusM");
    expect(at({ ...full(), extendedProperties: "[1]" })).toBe("extendedProperties");
    expect(at({ ...full(), extendedProperties: "{" })).toBe("extendedProperties");
    expect(at(full())).toBeNull();
  });

  it("flags WGS84 as this project's extension (Z-05), and only it", () => {
    expect(extensionRefs({ lower: 0, lowerReference: "WGS84", upper: 10, upperReference: "WGS84", uom: "m" })).toEqual(["WGS84"]);
    expect(extensionRefs(full().layer)).toEqual([]);
  });
});

describe("rings", () => {
  it("names each line that is not a WGS84 position", () => {
    const r = parseRings("44.7 41.6\nfoo\n200 0\n44.8 41.6\n44.8 41.7");
    expect(r.problems).toEqual([
      { ring: 1, line: 2, reason: "position" },
      { ring: 1, line: 3, reason: "range" },
    ]);
  });

  it("a blank line starts a hole; an already closed ring is not closed twice", () => {
    const r = parseRings("0 0\n1 0\n1 1\n0 0\n\n0.2 0.2\n0.4 0.2\n0.4 0.4");
    expect(r.problems).toEqual([]);
    expect(r.rings[0]).toHaveLength(4);
    expect(r.rings[1]).toHaveLength(4);
    expect(ringsText(r.rings)).toBe("0 0\n1 0\n1 1\n\n0.2 0.2\n0.4 0.2\n0.4 0.4");
  });

  it("no positions is too few, not an empty polygon", () => {
    expect(parseRings("").problems).toEqual([{ ring: 1, line: 0, reason: "too_few" }]);
  });
});

describe("fromFeature", () => {
  it("reads a feature back into the values it was built from", () => {
    const v = full();
    const back = fromFeature(toFeature(v), "GEO");
    expect(back.editable).toBe(true);
    if (!back.editable) return;
    expect(back.extra).toEqual({});
    expect(toFeature(back.values, back.extra)).toEqual(toFeature(v));
  });

  it("keeps the properties it has no field for, unchanged", () => {
    const f = toFeature(full());
    (f["properties"] as Record<string, unknown>)["futureMember"] = { a: 1 };
    ((f["properties"] as Record<string, unknown>)["dataSource"] as Record<string, unknown>)["creationDate"] = "2026-08-01T00:00:00Z";
    const back = fromFeature(f, null);
    if (!back.editable) throw new Error("not editable");
    const again = toFeature(back.values, back.extra)["properties"] as Record<string, unknown>;
    expect(again["futureMember"]).toEqual({ a: 1 });
    expect((again["dataSource"] as Record<string, unknown>)["creationDate"]).toBe("2026-08-01T00:00:00Z");
  });

  it("leaves out the members api writes itself, when told", () => {
    const f = toFeature({ ...full(), extendedProperties: '{"uspace_requirements": {"x": 1}, "note": "kept"}' });
    const back = fromFeature(f, null, ["uspace_requirements"]);
    if (!back.editable) throw new Error("not editable");
    expect(JSON.parse(back.values.extendedProperties)).toEqual({ note: "kept" });
  });

  it("a geometry collection is not editable here (the pair of the two above)", () => {
    expect(fromFeature({ type: "Feature", geometry: { type: "GeometryCollection", geometries: [] }, properties: {} }, null)).toEqual({ editable: false, reason: "geometry" });
  });
});

describe("the U-space designation", () => {
  it("is the 03 §1 shape api takes, with the Art. 3(4) members", () => {
    const d = designationOf({
      ...emptyDesignation(),
      airspace_name: "Test U-space",
      services_required: ["NID", "GEO", "FA", "TI"],
      uas_requirements: '{"rid": "network"}',
      operational_conditions: "",
      nid_update_hz: 1,
      ti_update_hz: 1,
      cis_latency_s: 5,
      service_performance_extra: "",
      max_height_agl_m: 120,
      airspace_constraints_extra: "",
      adjacent_ids: "TSU002, TSU003",
      in_controlled_airspace: true,
      ats_provider_id: "ANSP-TEST",
      cisp_id: "CISP-TEST",
      designation_ref: "TEST-DES-1",
      aip_ref: "TEST-AIP-1",
      risk_assessment_ref: "TEST-RA-1",
    });
    expect(d).toEqual({
      airspace_name: "Test U-space",
      services_required: ["NID", "GEO", "FA", "TI"],
      uas_requirements: { rid: "network" },
      service_performance: { nid_update_hz: 1, ti_update_hz: 1, cis_latency_s: 5 },
      operational_conditions: {},
      airspace_constraints: { max_height_agl_m: 120 },
      adjacent_ids: ["TSU002", "TSU003"],
      risk_assessment_ref: "TEST-RA-1",
      in_controlled_airspace: true,
      ats_provider_id: "ANSP-TEST",
      cisp_id: "CISP-TEST",
      designation_ref: "TEST-DES-1",
      aip_ref: "TEST-AIP-1",
    });
    const feature = toFeature({
      ...full(),
      identifier: "TSU001",
      type: "USPACE",
      reason: [],
      otherReasonInfo: [],
      extendedProperties: "",
      limitedApplicability: [],
    });
    pinned("uspace.json", { feature, designated_from: PERIOD.valid_from, designated_to: PERIOD.valid_to, designation: { ...d, adjacent_ids: [] } });
  });
});

describe("diff", () => {
  it("lists every changed leaf with its path, and nothing that did not change", () => {
    const a = { properties: { name: [{ text: "A" }], type: "PROHIBITED" }, layer: { upper: 120 } };
    const b = { properties: { name: [{ text: "B" }], type: "PROHIBITED" }, layer: { upper: 120, lower: 0 } };
    expect(diff(a, b)).toEqual({
      changes: [
        { path: "layer.lower", before: null, after: "0" },
        { path: "properties.name[0].text", before: '"A"', after: '"B"' },
      ],
      truncated: false,
    });
    expect(diff(a, a)).toEqual({ changes: [], truncated: false });
  });

  it("is bounded, and says so past its bound (E-10)", () => {
    const big = (n: number, v: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, v]));
    expect(diff(big(DIFF_MAX, 1), big(DIFF_MAX, 2)).truncated).toBe(false);
    const r = diff(big(DIFF_MAX + 1, 1), big(DIFF_MAX + 1, 2));
    expect(r.truncated).toBe(true);
    expect(r.changes).toHaveLength(DIFF_MAX);
  });
});
