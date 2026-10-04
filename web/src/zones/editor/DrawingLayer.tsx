"use client";

// The zone being drawn, on the editor's map: a click adds a position to
// the polygon's ring (or places the circle's centre), and the positions
// typed or clicked are drawn as they are, a line through them and a dot
// on each. Nothing is computed: the ring is closed by repeating the
// first position, and a circle shows its centre only, because drawing
// its edge is geodesy (CLAUDE.md rule 3); its radius is in the form.
import { useEffect, useMemo } from "react";
import type { GeoJSONSource, MapMouseEvent } from "maplibre-gl";
import { useLayer, resolveColour } from "@rootxkit/uspace-ui/layers";
import { parsePosition, type GeometryValues } from "./model";

/** Decimals a click is kept to: about 0.1 m. A display rounding, not a judgement. */
export const CLICK_DECIMALS = 6;

const SOURCE = "authoring-draft";

type Draft = GeoJSON.FeatureCollection;

/** What is drawn for the values: the ring's line and its positions, or the circle's centre. */
export function draftOf(g: GeometryValues): Draft {
  const features: GeoJSON.Feature[] = [];
  if (g.kind === "circle") {
    if (g.centerLng !== null && g.centerLat !== null) {
      features.push({ type: "Feature", properties: { role: "centre" }, geometry: { type: "Point", coordinates: [g.centerLng, g.centerLat] } });
    }
    return { type: "FeatureCollection", features };
  }
  for (const block of g.rings.split(/\r?\n\s*\r?\n/)) {
    const pts = block
      .split(/\r?\n/)
      .map(parsePosition)
      .filter((p): p is [number, number] => p !== null);
    for (const p of pts) features.push({ type: "Feature", properties: { role: "vertex" }, geometry: { type: "Point", coordinates: p } });
    const first = pts[0];
    if (pts.length >= 2 && first !== undefined) {
      features.push({ type: "Feature", properties: { role: "ring" }, geometry: { type: "LineString", coordinates: [...pts, first] } });
    }
  }
  return { type: "FeatureCollection", features };
}

export function DrawingLayer({ geometry, onClick }: { geometry: GeometryValues; onClick(lng: number, lat: number): void }) {
  const data = useMemo(() => draftOf(geometry), [geometry]);
  const map = useLayer<Draft>({
    id: SOURCE,
    data,
    build: (m) => {
      const colour = resolveColour(m, "--us-brand-accent");
      m.addSource(SOURCE, { type: "geojson", data: { type: "FeatureCollection", features: [] } });
      m.addLayer({ id: `${SOURCE}-line`, type: "line", source: SOURCE, filter: ["==", ["get", "role"], "ring"], paint: { "line-color": colour, "line-width": 2, "line-dasharray": [2, 1] } });
      m.addLayer({ id: `${SOURCE}-points`, type: "circle", source: SOURCE, filter: ["!=", ["get", "role"], "ring"], paint: { "circle-color": colour, "circle-radius": 4 } });
      return [`${SOURCE}-line`, `${SOURCE}-points`];
    },
    update: (m, d) => {
      (m.getSource(SOURCE) as GeoJSONSource | undefined)?.setData(d);
    },
  });
  useEffect(() => {
    if (map === null) return;
    const handler = (e: MapMouseEvent) => onClick(Number(e.lngLat.lng.toFixed(CLICK_DECIMALS)), Number(e.lngLat.lat.toFixed(CLICK_DECIMALS)));
    map.on("click", handler);
    return () => {
      map.off("click", handler);
    };
  }, [map, onClick]);
  return null;
}
