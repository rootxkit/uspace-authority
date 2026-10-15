// The published geo-zones (GET /v1/zones?state=published) as the kit's
// ZoneView. It copies what api said and decides nothing: the geometry is
// passed as published when GeoJSON can draw it (Polygon, MultiPolygon);
// a circle (a Point with a Circle extent) is drawn by the outline api drew
// for it (GET /v1/outlines/circle, uspace-core's geodesy) and is listed as
// not drawn while it has none, never approximated here, because drawing a
// circle is geodesy and geodesy is uspace-core's (CLAUDE.md rule 3).
// Anything else is listed as not drawn. Limits are passed only
// when published in metres; `applies` is null because api states no
// applicability on this read, and the kit draws such a zone in full.
import { isVerticalRef, isZoneType, type ZoneView } from "@rootxkit/uspace-ui/model";
import type { Lang } from "@rootxkit/uspace-ui/i18n";
import type { components } from "../api/types";

export type ZoneVersion = components["schemas"]["ZoneVersion"];

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | null => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Obj) : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** The text of an ED-318 TextShortType list in `lang`, else the first one. */
export function localText(v: unknown, lang: Lang): string | null {
  if (!Array.isArray(v)) return typeof v === "string" ? v : null;
  const items = v.map(obj).filter((x): x is Obj => x !== null && typeof x["text"] === "string");
  const want = lang === "ka" ? "ka" : "en";
  const hit = items.find((x) => typeof x["lang"] === "string" && x["lang"].toLowerCase().startsWith(want)) ?? items[0];
  return hit === undefined ? null : (hit["text"] as string);
}

const DRAWABLE = new Set(["Polygon", "MultiPolygon"]);

/** A published circle's centre and radius (ED-318: a Point with a Circle extent), or null for any other geometry. */
export function circleOf(z: ZoneVersion): { lat: number; lng: number; radiusM: number } | null {
  const geometry = obj(obj(z.feature)?.["geometry"]);
  if (geometry?.["type"] !== "Point" || obj(geometry["extent"])?.["subType"] !== "Circle") return null;
  const c = Array.isArray(geometry["coordinates"]) ? (geometry["coordinates"] as unknown[]) : [];
  const lng = num(c[0]);
  const lat = num(c[1]);
  const radiusM = num(obj(geometry["extent"])?.["radius"]);
  return lng === null || lat === null || radiusM === null ? null : { lat, lng, radiusM };
}

/** The key a circle's outline is asked for and kept under. */
export function circleKey(c: { lat: number; lng: number; radiusM: number }): string {
  return `${c.lat},${c.lng},${c.radiusM}`;
}

export type ZoneAdapted = { drawn: true; view: ZoneView } | { drawn: false; identifier: string; reason: "geometry" | "type" };

/** One zone version as a ZoneView, or why it is not drawn; a circle is drawn with `circleOutline`, api's outline of it. */
export function adaptZone(z: ZoneVersion, lang: Lang, circleOutline?: GeoJSON.Polygon | null): ZoneAdapted {
  const feature = obj(z.feature);
  const p = obj(feature?.["properties"]);
  const geometry = obj(feature?.["geometry"]);
  const type = p?.["type"] ?? z.type;
  if (!isZoneType(type)) return { drawn: false, identifier: z.identifier, reason: "type" };
  const circle = circleOf(z) !== null && circleOutline !== undefined && circleOutline !== null ? circleOutline : null;
  if (circle === null && (geometry === null || typeof geometry["type"] !== "string" || !DRAWABLE.has(geometry["type"]))) {
    return { drawn: false, identifier: z.identifier, reason: "geometry" };
  }
  if (geometry === null) return { drawn: false, identifier: z.identifier, reason: "geometry" };
  const layer = obj(geometry["layer"]);
  const metres = layer !== null && (layer["uom"] === undefined || layer["uom"] === "m");
  const lowerRef = layer?.["lowerReference"];
  const upperRef = layer?.["upperReference"];
  return {
    drawn: true,
    view: {
      identifier: z.identifier,
      name: localText(p?.["name"], lang),
      type,
      variant: typeof p?.["variant"] === "string" ? p["variant"] : null,
      reason: Array.isArray(p?.["reason"]) ? (p["reason"] as unknown[]).filter((r): r is string => typeof r === "string") : [],
      message: localText(p?.["message"], lang),
      lowerLimitM: metres ? num(layer?.["lower"]) : null,
      lowerRef: isVerticalRef(lowerRef) ? lowerRef : null,
      upperLimitM: metres ? num(layer?.["upper"]) : null,
      upperRef: isVerticalRef(upperRef) ? upperRef : null,
      geometry: (circle ?? { type: geometry["type"], coordinates: geometry["coordinates"] }) as unknown as ZoneView["geometry"],
      applies: null,
      restrictionState: null,
      version: z.published_version === undefined ? String(z.zone_version) : String(z.published_version),
      updatedAt: z.published_at ?? null,
    },
  };
}
