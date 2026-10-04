// The zone editor's values and the ED-318 feature they stand for (WP-22;
// spec 09 §1.6). Every member is named as ED-318 names it, as
// uspace-core v1.4.0 ed318 reads it (parse.go zoneFields, authorityFields,
// periodFields, dailyFields and the enumerations beside them); the
// feature this builds is checked by api with core's ed318.Parse, and
// internal/zonesvc/webeditor_test.go runs that check on this module's
// fixtures (test/fixtures/zone-editor/*.json). Nothing here judges: no
// geometry is computed, a circle is its centre and radius (LESSONS
// Z-11), and a ring is the author's positions with the first repeated at
// the end.

/** ED-318 zone types (core ed318 zoneTypeValues; REQ_AUTHORIZATION with a Z). */
export const ZONE_TYPES = ["PROHIBITED", "REQ_AUTHORIZATION", "CONDITIONAL", "NO_RESTRICTION", "USPACE"] as const;
/** ED-318 variants (core ed318 variantValues; CUSTOMIZED with a Z). */
export const VARIANTS = ["COMMON", "CUSTOMIZED"] as const;
/** ED-318 reasons (core ed318 reasonValues). */
export const REASONS = ["AIR_TRAFFIC", "SENSITIVE", "PRIVACY", "POPULATION", "NATURE", "NOISE", "EMERGENCY", "DAR", "OTHER"] as const;
/** zoneAuthority purposes (core ed318 purposeValues). */
export const PURPOSES = ["AUTHORIZATION", "NOTIFICATION", "INFORMATION"] as const;
/** Days of a schedule (core ed318 dayValues). */
export const DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN", "ANY"] as const;
/** Daylight events (core ed318 eventValues). */
export const EVENTS = ["BMCT", "SR", "SS", "EECT"] as const;
/**
 * Vertical references. WGS84 (height above the ellipsoid) is this
 * project's extension, not a published ED-318 reference (LESSONS Z-05);
 * api lists it in the version's `extensions` and the editor says so.
 */
export const VERTICAL_REFS = ["AGL", "AMSL", "WGS84"] as const;
export const EXTENSION_REFS: readonly string[] = ["WGS84"];
/** A layer's units (core ed318 UomMetres, UomFeet); absent means metres (UNVERIFIED, docs/runbooks/zones.md). */
export const UOMS = ["m", "ft"] as const;
/** The text languages offered for a textShortType entry (at most five characters, core ed318 Text). */
export const TEXT_LANGS = ["en-GB", "ka-GE"] as const;
/** api's identifier rule: at most 7 characters (docs/runbooks/zones.md). */
export const IDENTIFIER_MAX = 7;

export type ZoneTypeValue = (typeof ZONE_TYPES)[number];

export interface TextEntry {
  text: string;
  lang: string;
}

export interface DailyValues {
  day: string[];
  start: "time" | "event";
  startTime: string;
  startEvent: string;
  end: "time" | "event";
  endTime: string;
  endEvent: string;
}

export interface PeriodValues {
  startDateTime: string | null;
  endDateTime: string | null;
  schedule: DailyValues[];
}

export interface AuthorityValues {
  /** The language of the three texts below. */
  lang: string;
  name: string;
  service: string;
  contactName: string;
  siteURL: string;
  email: string;
  phone: string;
  purpose: string;
  intervalBefore: string;
}

export interface GeometryValues {
  kind: "polygon" | "circle";
  /** One position per line, "longitude latitude" in WGS84 degrees; a blank line starts the next ring (a hole). */
  rings: string;
  centerLng: number | null;
  centerLat: number | null;
  /** The circle's radius, metres (whatever the layer's uom; UNVERIFIED, docs/runbooks/zones.md). */
  radiusM: number | null;
}

export interface LayerValues {
  lower: number | null;
  lowerReference: string;
  upper: number | null;
  upperReference: string;
  uom: string;
}

export interface ZoneEditorValues {
  identifier: string;
  country: string;
  name: TextEntry[];
  type: string;
  variant: string;
  restrictionConditions: string;
  region: number | null;
  reason: string[];
  otherReasonInfo: TextEntry[];
  regulationExemption: string;
  message: TextEntry[];
  /** extendedProperties as JSON text (an object); empty for none. */
  extendedProperties: string;
  limitedApplicability: PeriodValues[];
  zoneAuthority: AuthorityValues[];
  dataSource: { creationDateTime: string | null; updateDateTime: string | null; originatorText: string; originatorLang: string };
  geometry: GeometryValues;
  layer: LayerValues;
}

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | null => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Obj) : null);
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export function emptyAuthority(lang: string): AuthorityValues {
  return { lang, name: "", service: "", contactName: "", siteURL: "", email: "", phone: "", purpose: "", intervalBefore: "" };
}

export function emptyDaily(): DailyValues {
  return { day: [], start: "time", startTime: "", startEvent: "", end: "time", endTime: "", endEvent: "" };
}

export function emptyPeriod(): PeriodValues {
  return { startDateTime: null, endDateTime: null, schedule: [] };
}

/** A new zone's values: nothing chosen for the author, the country only when configured. */
export function emptyValues(opts: { country: string | null; type?: ZoneTypeValue }): ZoneEditorValues {
  return {
    identifier: "",
    country: opts.country ?? "",
    name: [
      { text: "", lang: "en-GB" },
      { text: "", lang: "ka-GE" },
    ],
    type: opts.type ?? "",
    variant: "COMMON",
    restrictionConditions: "",
    region: null,
    reason: [],
    otherReasonInfo: [],
    regulationExemption: "",
    message: [],
    extendedProperties: "",
    limitedApplicability: [],
    zoneAuthority: [emptyAuthority("en-GB")],
    dataSource: { creationDateTime: null, updateDateTime: null, originatorText: "", originatorLang: "en-GB" },
    geometry: { kind: "polygon", rings: "", centerLng: null, centerLat: null, radiusM: null },
    layer: { lower: null, lowerReference: "", upper: null, upperReference: "", uom: "m" },
  };
}

/** A position line's two numbers, or null when the line is not "lng lat". */
export function parsePosition(line: string): [number, number] | null {
  const parts = line.trim().split(/[\s,;]+/).filter((p) => p !== "");
  if (parts.length !== 2) return null;
  const lng = Number(parts[0]);
  const lat = Number(parts[1]);
  if (!Number.isFinite(lng) || !Number.isFinite(lat)) return null;
  return [lng, lat];
}

export interface RingProblem {
  ring: number;
  line: number;
  reason: "position" | "range" | "too_few";
}

/**
 * The rings typed or drawn, each closed by repeating its first position
 * when the author did not, with every line that is not a WGS84 position
 * named. A ring needs three distinct positions to be one. api checks
 * everything else (self-crossing, vertex bounds) with core.
 */
export function parseRings(text: string): { rings: [number, number][][]; problems: RingProblem[] } {
  const blocks = text.split(/\r?\n\s*\r?\n/).map((b) => b.split(/\r?\n/).filter((l) => l.trim() !== ""));
  const rings: [number, number][][] = [];
  const problems: RingProblem[] = [];
  blocks
    .filter((b) => b.length > 0)
    .forEach((lines, ri) => {
      const ring: [number, number][] = [];
      lines.forEach((l, li) => {
        const p = parsePosition(l);
        if (p === null) problems.push({ ring: ri + 1, line: li + 1, reason: "position" });
        else if (p[0] < -180 || p[0] > 180 || p[1] < -90 || p[1] > 90) problems.push({ ring: ri + 1, line: li + 1, reason: "range" });
        else ring.push(p);
      });
      const first = ring[0];
      const last = ring[ring.length - 1];
      if (first !== undefined && last !== undefined && (first[0] !== last[0] || first[1] !== last[1])) ring.push([first[0], first[1]]);
      if (ring.length < 4) problems.push({ ring: ri + 1, line: 0, reason: "too_few" });
      rings.push(ring);
    });
  if (rings.length === 0) problems.push({ ring: 1, line: 0, reason: "too_few" });
  return { rings, problems };
}

/** Rings as the editor's text: one "lng lat" per line, rings apart by a blank line, the closing repeat left out. */
export function ringsText(rings: unknown): string {
  if (!Array.isArray(rings)) return "";
  return rings
    .map((r) => {
      if (!Array.isArray(r)) return "";
      const pts = r.filter((p): p is [number, number] => Array.isArray(p) && typeof p[0] === "number" && typeof p[1] === "number");
      const first = pts[0];
      const last = pts[pts.length - 1];
      const open = pts.length > 1 && first !== undefined && last !== undefined && first[0] === last[0] && first[1] === last[1] ? pts.slice(0, -1) : pts;
      return open.map((p) => `${p[0]} ${p[1]}`).join("\n");
    })
    .join("\n\n");
}

const texts = (list: readonly TextEntry[]) => list.filter((e) => e.text.trim() !== "").map((e) => ({ text: e.text.trim(), lang: e.lang }));
const text1 = (t: string, lang: string) => (t.trim() === "" ? undefined : [{ text: t.trim(), lang }]);
const optStr = (s: string) => (s.trim() === "" ? undefined : s.trim());

function dropUndefined(o: Obj): Obj {
  const out: Obj = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === undefined) continue;
    if (Array.isArray(v) && v.length === 0) continue;
    out[k] = v;
  }
  return out;
}

export class EditorProblem extends Error {
  constructor(
    readonly field: string,
    readonly key: string,
  ) {
    super(`${field}: ${key}`);
  }
}

/** extendedProperties' text as an object, or the problem with it. */
export function parseExtended(text: string): Obj | null {
  if (text.trim() === "") return null;
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new EditorProblem("extendedProperties", "authority.zone.e.extended_json");
  }
  const o = obj(v);
  if (o === null) throw new EditorProblem("extendedProperties", "authority.zone.e.extended_object");
  return o;
}

/** The geometry ED-318 carries, with its layer; a circle is a Point with a Circle extent (centre and radius, Z-11). */
export function geometryOf(g: GeometryValues, layer: LayerValues): Obj {
  const l = dropUndefined({
    upper: layer.upper ?? undefined,
    upperReference: optStr(layer.upperReference),
    lower: layer.lower ?? undefined,
    lowerReference: optStr(layer.lowerReference),
    uom: optStr(layer.uom),
  });
  if (g.kind === "circle") {
    if (g.centerLng === null || g.centerLat === null) throw new EditorProblem("geometry.center", "authority.zone.e.center");
    if (g.radiusM === null || !(g.radiusM > 0)) throw new EditorProblem("geometry.radiusM", "authority.zone.e.radius");
    return { type: "Point", coordinates: [g.centerLng, g.centerLat], extent: { subType: "Circle", radius: g.radiusM }, layer: l };
  }
  const { rings, problems } = parseRings(g.rings);
  if (problems.length > 0) throw new EditorProblem("geometry.rings", "authority.zone.e.rings");
  return { type: "Polygon", coordinates: rings, layer: l };
}

function dailyOf(d: DailyValues): Obj {
  return dropUndefined({
    day: d.day.length === 0 ? undefined : d.day,
    startTime: d.start === "time" ? optStr(d.startTime) : undefined,
    startEvent: d.start === "event" ? optStr(d.startEvent) : undefined,
    endTime: d.end === "time" ? optStr(d.endTime) : undefined,
    endEvent: d.end === "event" ? optStr(d.endEvent) : undefined,
  });
}

/**
 * The ED-318 feature of the editor's values, with every member the
 * author left empty left out. `extra` carries the properties of an
 * existing version the editor has no field for, unchanged.
 */
export function toFeature(v: ZoneEditorValues, extra: Obj = {}): Obj {
  const ext = parseExtended(v.extendedProperties);
  const ds = dropUndefined({
    ...(obj(extra["dataSource"]) ?? {}),
    creationDateTime: v.dataSource.creationDateTime ?? undefined,
    updateDateTime: v.dataSource.updateDateTime ?? undefined,
    originator: v.dataSource.originatorText.trim() === "" ? undefined : { text: v.dataSource.originatorText.trim(), lang: v.dataSource.originatorLang },
  });
  const properties = dropUndefined({
    ...extra,
    identifier: v.identifier.trim(),
    country: v.country.trim(),
    name: texts(v.name),
    type: v.type,
    variant: optStr(v.variant),
    restrictionConditions: optStr(v.restrictionConditions),
    region: v.region ?? undefined,
    reason: v.reason.length === 0 ? undefined : REASONS.filter((r) => v.reason.includes(r)),
    otherReasonInfo: texts(v.otherReasonInfo),
    regulationExemption: optStr(v.regulationExemption),
    message: texts(v.message),
    extendedProperties: ext ?? undefined,
    limitedApplicability: v.limitedApplicability.map((p) =>
      dropUndefined({
        startDateTime: p.startDateTime ?? undefined,
        endDateTime: p.endDateTime ?? undefined,
        schedule: p.schedule.map(dailyOf),
      }),
    ),
    zoneAuthority: v.zoneAuthority.map((a) =>
      dropUndefined({
        name: text1(a.name, a.lang),
        service: text1(a.service, a.lang),
        contactName: text1(a.contactName, a.lang),
        siteURL: optStr(a.siteURL),
        email: optStr(a.email),
        phone: optStr(a.phone),
        purpose: a.purpose,
        intervalBefore: optStr(a.intervalBefore),
      }),
    ),
    dataSource: Object.keys(ds).length === 0 ? undefined : ds,
  });
  return { type: "Feature", geometry: geometryOf(v.geometry, v.layer), properties };
}

const KNOWN_PROPERTIES = new Set([
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
]);

function textEntries(v: unknown): TextEntry[] {
  if (!Array.isArray(v)) return [];
  return v.map(obj).filter((x): x is Obj => x !== null).map((x) => ({ text: str(x["text"]), lang: str(x["lang"]) }));
}

function firstText(v: unknown): { text: string; lang: string } | null {
  return textEntries(v)[0] ?? null;
}

export type FromFeature =
  | { editable: true; values: ZoneEditorValues; extra: Obj }
  /** A geometry the editor does not draw (a GeometryCollection of layers): revise it by import. */
  | { editable: false; reason: "geometry" };

/**
 * The editor's values for an existing version's feature, and the
 * properties it has no field for. `dropExtended` names members of
 * extendedProperties api writes itself (a U-space airspace's
 * `uspace_requirements`, which a revision must not bring back).
 */
export function fromFeature(feature: unknown, country: string | null, dropExtended: readonly string[] = []): FromFeature {
  const f = obj(feature);
  const p = obj(f?.["properties"]) ?? {};
  const g = obj(f?.["geometry"]) ?? {};
  const base = emptyValues({ country });
  let geometry: GeometryValues;
  if (g["type"] === "Polygon") {
    geometry = { ...base.geometry, kind: "polygon", rings: ringsText(g["coordinates"]) };
  } else if (g["type"] === "Point" && obj(g["extent"])?.["subType"] === "Circle") {
    const c = Array.isArray(g["coordinates"]) ? (g["coordinates"] as unknown[]) : [];
    geometry = { kind: "circle", rings: "", centerLng: num(c[0]), centerLat: num(c[1]), radiusM: num(obj(g["extent"])?.["radius"]) };
  } else {
    return { editable: false, reason: "geometry" };
  }
  const layer = obj(g["layer"]) ?? {};
  const extra: Obj = {};
  for (const [k, v] of Object.entries(p)) if (!KNOWN_PROPERTIES.has(k)) extra[k] = v;
  const ds = obj(p["dataSource"]) ?? {};
  // The members of dataSource the editor has no field for travel unchanged.
  const dsExtra: Obj = {};
  for (const [k, v] of Object.entries(ds)) if (!["creationDateTime", "updateDateTime", "originator"].includes(k)) dsExtra[k] = v;
  const orig = obj(ds["originator"]);
  const values: ZoneEditorValues = {
    identifier: str(p["identifier"]),
    country: str(p["country"]),
    name: textEntries(p["name"]),
    type: str(p["type"]),
    variant: str(p["variant"]),
    restrictionConditions: str(p["restrictionConditions"]),
    region: num(p["region"]),
    reason: Array.isArray(p["reason"]) ? (p["reason"] as unknown[]).filter((r): r is string => typeof r === "string") : [],
    otherReasonInfo: textEntries(p["otherReasonInfo"]),
    regulationExemption: str(p["regulationExemption"]),
    message: textEntries(p["message"]),
    extendedProperties: extendedText(obj(p["extendedProperties"]), dropExtended),
    limitedApplicability: (Array.isArray(p["limitedApplicability"]) ? (p["limitedApplicability"] as unknown[]) : []).map((x) => {
      const o = obj(x) ?? {};
      return {
        startDateTime: str(o["startDateTime"]) || null,
        endDateTime: str(o["endDateTime"]) || null,
        schedule: (Array.isArray(o["schedule"]) ? (o["schedule"] as unknown[]) : []).map((d) => {
          const s = obj(d) ?? {};
          return {
            day: Array.isArray(s["day"]) ? (s["day"] as unknown[]).filter((x): x is string => typeof x === "string") : [],
            start: typeof s["startEvent"] === "string" ? "event" : "time",
            startTime: str(s["startTime"]),
            startEvent: str(s["startEvent"]),
            end: typeof s["endEvent"] === "string" ? "event" : "time",
            endTime: str(s["endTime"]),
            endEvent: str(s["endEvent"]),
          } satisfies DailyValues;
        }),
      };
    }),
    zoneAuthority: (Array.isArray(p["zoneAuthority"]) ? (p["zoneAuthority"] as unknown[]) : []).map((x) => {
      const a = obj(x) ?? {};
      const n = firstText(a["name"]);
      return {
        lang: n?.lang ?? firstText(a["service"])?.lang ?? "en-GB",
        name: n?.text ?? "",
        service: firstText(a["service"])?.text ?? "",
        contactName: firstText(a["contactName"])?.text ?? "",
        siteURL: str(a["siteURL"]),
        email: str(a["email"]),
        phone: str(a["phone"]),
        purpose: str(a["purpose"]),
        intervalBefore: str(a["intervalBefore"]),
      };
    }),
    dataSource: {
      creationDateTime: str(ds["creationDateTime"]) || null,
      updateDateTime: str(ds["updateDateTime"]) || null,
      originatorText: str(orig?.["text"]),
      originatorLang: str(orig?.["lang"]) || "en-GB",
    },
    geometry,
    layer: {
      lower: num(layer["lower"]),
      lowerReference: str(layer["lowerReference"]),
      upper: num(layer["upper"]),
      upperReference: str(layer["upperReference"]),
      uom: str(layer["uom"]) || "m",
    },
  };
  if (Object.keys(dsExtra).length > 0) extra["dataSource"] = dsExtra;
  return { editable: true, values, extra };
}

function extendedText(ext: Obj | null, drop: readonly string[]): string {
  if (ext === null) return "";
  const kept: Obj = {};
  for (const [k, v] of Object.entries(ext)) if (!drop.includes(k)) kept[k] = v;
  return Object.keys(kept).length === 0 ? "" : JSON.stringify(kept, null, 2);
}

/** The references the values use that are this project's extension (Z-05). */
export function extensionRefs(layer: LayerValues): string[] {
  return [layer.lowerReference, layer.upperReference].filter((r, i, a) => EXTENSION_REFS.includes(r) && a.indexOf(r) === i);
}
