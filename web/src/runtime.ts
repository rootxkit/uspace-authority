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
  return {
    mapView: "view" in map ? map.view : null,
    mapViewProblem: "problem" in map ? map.problem : null,
  };
}
