// The published geo-zones (GET /v1/zones?state=published) as the kit's
// ZoneView. It copies what api said and decides nothing: the geometry is
// passed as published when GeoJSON can draw it (Polygon, MultiPolygon);
// a circle (a Point with an extent) or anything else is listed as not
// drawn, never approximated here, because drawing a circle is geodesy and
// geodesy is uspace-core's (CLAUDE.md rule 3). Limits are passed only
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

export type ZoneAdapted = { drawn: true; view: ZoneView } | { drawn: false; identifier: string; reason: "geometry" | "type" };

/** One zone version as a ZoneView, or why it is not drawn. */
export function adaptZone(z: ZoneVersion, lang: Lang): ZoneAdapted {
  const feature = obj(z.feature);
  const p = obj(feature?.["properties"]);
  const geometry = obj(feature?.["geometry"]);
  const type = p?.["type"] ?? z.type;
  if (!isZoneType(type)) return { drawn: false, identifier: z.identifier, reason: "type" };
  if (geometry === null || typeof geometry["type"] !== "string" || !DRAWABLE.has(geometry["type"])) {
    return { drawn: false, identifier: z.identifier, reason: "geometry" };
  }
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
      geometry: { type: geometry["type"], coordinates: geometry["coordinates"] } as unknown as ZoneView["geometry"],
      applies: null,
      restrictionState: null,
      version: z.published_version === undefined ? String(z.zone_version) : String(z.published_version),
      updatedAt: z.published_at ?? null,
    },
  };
}
