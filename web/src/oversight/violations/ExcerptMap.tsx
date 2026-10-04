"use client";

// The evidence excerpt on the kit's map: each segment a line through its
// own samples, each sample a point, and nothing across a hole (B-13).
// Without WebGL (a headless browser) the map is empty and the list
// beside it carries everything.
import { useSyncExternalStore } from "react";
import type { GeoJSONSource, Map as MapLibreMap } from "maplibre-gl";
import { useLang } from "@rootxkit/uspace-ui/i18n";
import { resolveColour, useLayer } from "@rootxkit/uspace-ui/layers";
import { MapView } from "@rootxkit/uspace-ui/map";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { excerptFeatures, type ExcerptView } from "./excerpt";

/** The first view of an excerpt: centred on its first sample. A display choice, not a place. */
export const EXCERPT_ZOOM = 15;

type Data = ReturnType<typeof excerptFeatures>;

function ExcerptLayer({ data }: { data: Data }) {
  useLayer<Data>({
    id: "authority-excerpt",
    data,
    build(map: MapLibreMap) {
      map.addSource("authority-excerpt-lines", { type: "geojson", data: data.lines });
      map.addSource("authority-excerpt-points", { type: "geojson", data: data.points });
      const colour = resolveColour(map, "--us-trust-broadcast");
      map.addLayer({ id: "authority-excerpt-line", type: "line", source: "authority-excerpt-lines", paint: { "line-color": colour, "line-width": 3 } });
      map.addLayer({
        id: "authority-excerpt-point",
        type: "circle",
        source: "authority-excerpt-points",
        paint: { "circle-color": colour, "circle-radius": 4, "circle-stroke-width": 1, "circle-stroke-color": resolveColour(map, "--us-surface-raised") },
      });
      return ["authority-excerpt-line", "authority-excerpt-point"];
    },
    update(map: MapLibreMap, d: Data) {
      (map.getSource("authority-excerpt-lines") as GeoJSONSource | undefined)?.setData(d.lines);
      (map.getSource("authority-excerpt-points") as GeoJSONSource | undefined)?.setData(d.points);
    },
  });
  return null;
}

function noSubscribe(): () => void {
  return () => undefined;
}

export function ExcerptMap({ view }: { view: ExcerptView }) {
  const { lang } = useLang();
  const { resolved } = useTheme();
  const origin = useSyncExternalStore(
    noSubscribe,
    () => window.location.origin,
    () => null,
  );
  const data = excerptFeatures(view);
  if (origin === null || data.first === null) return null;
  return (
    <div className="relative h-80 w-full" data-testid="excerpt-map">
      <MapView
        className="absolute inset-0"
        basemap={{ baseUrl: origin }}
        initial={{ center: data.first, zoom: EXCERPT_ZOOM, bearing: 0, pitch: 0 }}
        lang={lang}
        scheme={resolved}
      >
        <ExcerptLayer data={data} />
      </MapView>
    </div>
  );
}
