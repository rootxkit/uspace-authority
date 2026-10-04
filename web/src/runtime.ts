// Values the server reads at request time and hands to the page. They
// are read through an injected environment so `next build` does not
// inline them: the image is built once in CI and configured at start.
// Coordinates are data (INV-03): with no first view configured the map
// names the variable instead of choosing a place.

/** The picture WebSocket, same-origin (M22): Caddy routes /v1/picture/* to picture-ws. */
export const PICTURE_WS_PATH = "/v1/picture/ws";

/** picture-ws's sources read (api/openapi.yaml getPictureSources), same-origin with the cookie. */
export const PICTURE_SOURCES_PATH = "/v1/picture/sources";

export interface MapViewConfig {
  /** [lng, lat], WGS84 degrees (WEB_MAP_CENTER "lng,lat"). */
  center: [number, number];
  /** WEB_MAP_ZOOM. */
  zoom: number;
}

export interface RuntimeConfig {
  /** The inspector map's first view; null when not configured or not valid. */
  mapView: MapViewConfig | null;
  /** Why mapView is null, naming the variable; null when it is set. */
  mapViewProblem: string | null;
  /**
   * The purposes a person may state for reading personal data in the
   * registry (WEB_PII_PURPOSES); each is sent as the request's `purpose`.
   */
  piiPurposes: string[];
  /** Why piiPurposes is the default, or what was wrong with the variable; null when it is set and valid. */
  piiPurposesProblem: string | null;
  /** The ED-318 `country` a new zone starts with (WEB_ZONE_COUNTRY, ISO 3166-1 alpha-3); null: the author types it. */
  zoneCountry: string | null;
}

/**
 * The registry's PII purposes when WEB_PII_PURPOSES is unset. Pending
 * GCAA and the DPO (spec 06 §5, purpose limitation): no list is set by
 * law yet, so these are the demonstration's, marked as such where they
 * are shown, and replaced by configuration.
 */
export const DEFAULT_PII_PURPOSES: readonly string[] = ["registration_review", "oversight_inspection", "data_subject_request"];

const PURPOSE_CODE = /^[a-z][a-z0-9_]{0,63}$/;
/** At most this many purposes are offered (a bounded list). */
export const PII_PURPOSES_MAX = 20;

/** The purposes from their variable, or the default with the reason. */
export function parsePurposes(raw: string | undefined): { purposes: string[]; problem: string | null } {
  if (raw === undefined || raw.trim() === "") {
    return { purposes: [...DEFAULT_PII_PURPOSES], problem: "WEB_PII_PURPOSES is not set: the default purposes, pending GCAA" };
  }
  const items = raw.split(",").map((p) => p.trim()).filter((p) => p !== "");
  const bad = items.find((p) => !PURPOSE_CODE.test(p));
  if (bad !== undefined || items.length === 0 || items.length > PII_PURPOSES_MAX) {
    const why = bad !== undefined ? `${JSON.stringify(bad)} is not a lower-case code` : `want 1..${PII_PURPOSES_MAX} codes`;
    return { purposes: [...DEFAULT_PII_PURPOSES], problem: `WEB_PII_PURPOSES: ${why}; the default purposes, pending GCAA` };
  }
  return { purposes: [...new Set(items)], problem: null };
}

/** The country a new zone starts with, or null (unset or not three upper-case letters). */
export function parseZoneCountry(raw: string | undefined): string | null {
  const v = (raw ?? "").trim();
  return /^[A-Z]{3}$/.test(v) ? v : null;
}

/** The map's first view from its two variables, or the problem with them. */
export function parseMapView(center: string | undefined, zoom: string | undefined): { view: MapViewConfig } | { problem: string } {
  if (center === undefined || center.trim() === "") return { problem: "WEB_MAP_CENTER is not set" };
  if (zoom === undefined || zoom.trim() === "") return { problem: "WEB_MAP_ZOOM is not set" };
  const parts = center.split(",").map((p) => p.trim());
  const lng = Number(parts[0]);
  const lat = Number(parts[1]);
  if (parts.length !== 2 || parts.some((p) => p === "") || !Number.isFinite(lng) || !Number.isFinite(lat)) {
    return { problem: `WEB_MAP_CENTER: want "lng,lat", got ${JSON.stringify(center)}` };
  }
  if (lng < -180 || lng > 180 || lat < -90 || lat > 90) {
    return { problem: `WEB_MAP_CENTER: ${center} is outside WGS84 longitude -180..180, latitude -90..90` };
  }
  const z = Number(zoom);
  if (!Number.isFinite(z) || z < 0 || z > 22) return { problem: `WEB_MAP_ZOOM: want 0..22, got ${JSON.stringify(zoom)}` };
  return { view: { center: [lng, lat], zoom: z } };
}

export function runtimeConfig(env: Record<string, string | undefined>): RuntimeConfig {
  const map = parseMapView(env["WEB_MAP_CENTER"], env["WEB_MAP_ZOOM"]);
  const purposes = parsePurposes(env["WEB_PII_PURPOSES"]);
  return {
    mapView: "view" in map ? map.view : null,
    mapViewProblem: "problem" in map ? map.problem : null,
    piiPurposes: purposes.purposes,
    piiPurposesProblem: purposes.problem,
    zoneCountry: parseZoneCountry(env["WEB_ZONE_COUNTRY"]),
  };
}
