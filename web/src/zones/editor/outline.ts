"use client";

// The zone editor's geometry as the kit's drawing tool sees it (uspace-ui
// 1.0.0 layers/DrawLayer; docs/runbooks/web.md "The zone editor"). The
// form keeps the geometry as it always did, typed or clicked: a ring per
// block of "longitude latitude" lines, a blank line before each hole, or a
// circle's centre and radius. The map edits the outer ring and the centre
// only; the holes stay typed. A circle's outline on the map is the one api
// drew (GET /v1/outlines/circle, uspace-core geodesy): web/ draws no edge
// itself (CLAUDE.md rule 3). Nothing here judges a shape; api does, with
// core's ed318.Parse.
import { useEffect, useState } from "react";
import type { DrawOutline, DrawPoint } from "@rootxkit/uspace-ui/model";
import type { ConsoleClient } from "../../api/client";
import { parsePosition, type GeometryValues } from "./model";

/**
 * The most vertices of one ring: uspace-core's ed318.Parse takes at most
 * ed269.DefaultLimits.MaxRingVertices (5000) positions per ring, the last
 * repeating the first. internal/zonesvc/webeditor_test.go pins it.
 */
export const MAX_RING_VERTICES = 4999;

/** Decimals a point placed or moved on the map is written with: about 0.1 m. A display rounding, not a judgement. */
export const CLICK_DECIMALS = 6;

function rounded(v: number): number {
  return Number(v.toFixed(CLICK_DECIMALS));
}

const BLOCK = /\r?\n\s*\r?\n/;

/** The outer ring's typed lines, or null when one of them is not a position (the map then leaves the text alone). */
function outerRing(rings: string): DrawPoint[] | null {
  const first = rings.split(BLOCK)[0] ?? "";
  const out: DrawPoint[] = [];
  for (const line of first.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const p = parsePosition(line);
    if (p === null) return null;
    out.push({ lng: p[0], lat: p[1] });
  }
  return out;
}

/** What the drawing tool shows of the form's geometry, and whether the map may change it. */
export function outlineOf(g: GeometryValues): { outline: DrawOutline; editable: boolean } {
  if (g.kind === "circle") {
    const center = g.centerLng !== null && g.centerLat !== null ? { lat: g.centerLat, lng: g.centerLng } : null;
    return { outline: { kind: "circle", center, radiusM: g.radiusM }, editable: true };
  }
  const vertices = outerRing(g.rings);
  return vertices === null ? { outline: { kind: "polygon", vertices: [] }, editable: false } : { outline: { kind: "polygon", vertices }, editable: true };
}

/** The rings text with its outer ring replaced by `vertices`, the holes after it kept as typed. */
export function withOuterRing(rings: string, vertices: readonly DrawPoint[]): string {
  const blocks = rings.split(BLOCK);
  const outer = vertices.map((p) => `${rounded(p.lng)} ${rounded(p.lat)}`).join("\n");
  const holes = blocks.slice(1).filter((b) => b.trim() !== "");
  return [outer, ...holes].join("\n\n");
}

/** The circle's centre as the form's two numbers, written to the click's decimals. */
export function centreValues(p: DrawPoint): { centerLng: number; centerLat: number } {
  return { centerLng: rounded(p.lng), centerLat: rounded(p.lat) };
}

/** What the map shows of a circle: api's outline, or why it has none. */
export type CircleOutlineState = { kind: "none" } | { kind: "loading" } | { kind: "drawn"; outline: GeoJSON.Polygon } | { kind: "refused" };

/** The outline in an answer of GET /v1/outlines/circle, or null when it is not a ring. */
export function outlineOfAnswer(data: unknown): GeoJSON.Polygon | null {
  if (typeof data !== "object" || data === null) return null;
  const o = (data as { outline?: unknown }).outline;
  if (typeof o !== "object" || o === null) return null;
  const { type, coordinates } = o as { type?: unknown; coordinates?: unknown };
  if (type !== "Polygon" || !Array.isArray(coordinates) || coordinates.length < 1) return null;
  const ok = coordinates.every(
    (ring) => Array.isArray(ring) && ring.length >= 4 && ring.every((p) => Array.isArray(p) && p.length === 2 && p.every((n) => typeof n === "number" && Number.isFinite(n))),
  );
  return ok ? { type: "Polygon", coordinates: coordinates as GeoJSON.Position[][] } : null;
}

/**
 * The circle's outline as api drew it: asked again whenever the centre or
 * the radius changes, the previous request aborted, an answer for a circle
 * no longer shown dropped. A polygon, or a circle without its centre or
 * radius, has none.
 */
export function useCircleOutline(client: ConsoleClient, outline: DrawOutline): CircleOutlineState {
  const lat = outline.kind === "circle" ? (outline.center?.lat ?? null) : null;
  const lng = outline.kind === "circle" ? (outline.center?.lng ?? null) : null;
  const radiusM = outline.kind === "circle" ? outline.radiusM : null;
  const key = lat === null || lng === null || radiusM === null ? null : `${lat},${lng},${radiusM}`;
  const [state, setState] = useState<{ key: string | null; value: CircleOutlineState }>({ key: null, value: { kind: "none" } });
  useEffect(() => {
    if (key === null || lat === null || lng === null || radiusM === null) return;
    const ctrl = new AbortController();
    client
      .GET("/v1/outlines/circle", { params: { query: { lat, lng, radius_m: radiusM } }, signal: ctrl.signal })
      .then(({ data }) => {
        const drawn = outlineOfAnswer(data);
        setState({ key, value: drawn === null ? { kind: "refused" } : { kind: "drawn", outline: drawn } });
      })
      .catch(() => {
        if (!ctrl.signal.aborted) setState({ key, value: { kind: "refused" } });
      });
    return () => ctrl.abort();
  }, [client, key, lat, lng, radiusM]);
  if (key === null) return { kind: "none" };
  return state.key === key ? state.value : { kind: "loading" };
}
