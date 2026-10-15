"use client";

// A map of zone versions on uspace-ui's MapView and ZoneLayer: the
// versions as api sent them, drawn when GeoJSON can draw them, a circle
// by the outline api drew for it (GET /v1/outlines/circle; listed as not
// drawn until api answers, and when it refuses, src/zones/adapt.ts). The first view is the
// deployment's (WEB_MAP_CENTER, WEB_MAP_ZOOM); without one the map names
// the variable and the lists beside it still work.
import { useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { ZoneLayer } from "@rootxkit/uspace-ui/layers";
import { ZoneLegend } from "@rootxkit/uspace-ui/legend";
import { MapView } from "@rootxkit/uspace-ui/map";
import type { ZoneType, ZoneView } from "@rootxkit/uspace-ui/model";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { useRuntimeConfig } from "../components/Providers";
import { useConsole } from "../authoring/api";
import type { ConsoleClient } from "../api/client";
import { adaptZone, circleKey, circleOf, type ZoneVersion } from "./adapt";
import { outlineOfAnswer } from "./editor/outline";

/** The most circles one map asks api to draw; any more are listed as not drawn. A display bound. */
export const MAP_CIRCLES_MAX = 100;

function noSubscribe(): () => void {
  return () => undefined;
}

/** The versions as the kit's zone views, and the identifiers not drawn; a circle is drawn by its outline in `outlines` (api's). */
export function zoneViews(zones: readonly ZoneVersion[], lang: "ka" | "en", outlines: ReadonlyMap<string, GeoJSON.Polygon | null> = new Map()): { views: ZoneView[]; undrawn: string[] } {
  const views: ZoneView[] = [];
  const undrawn: string[] = [];
  for (const z of zones) {
    const c = circleOf(z);
    const a = adaptZone(z, lang, c === null ? undefined : (outlines.get(circleKey(c)) ?? null));
    if (a.drawn) views.push(a.view);
    else undrawn.push(a.identifier);
  }
  return { views, undrawn };
}

/**
 * api's outline of every circle among `zones` (at most MAP_CIRCLES_MAX):
 * null for one api refused or did not draw, absent while asked.
 */
export function useCircleOutlines(client: ConsoleClient, zones: readonly ZoneVersion[]): ReadonlyMap<string, GeoJSON.Polygon | null> {
  const circles = useMemo(() => {
    const m = new Map<string, { lat: number; lng: number; radiusM: number }>();
    for (const z of zones) {
      const c = circleOf(z);
      if (c !== null && m.size < MAP_CIRCLES_MAX) m.set(circleKey(c), c);
    }
    return m;
  }, [zones]);
  const [outlines, setOutlines] = useState<ReadonlyMap<string, GeoJSON.Polygon | null>>(new Map());
  useEffect(() => {
    const ctrl = new AbortController();
    for (const [key, c] of circles) {
      client
        .GET("/v1/outlines/circle", { params: { query: { lat: c.lat, lng: c.lng, radius_m: c.radiusM } }, signal: ctrl.signal })
        .then(({ data }) => {
          setOutlines((m) => new Map(m).set(key, outlineOfAnswer(data)));
        })
        .catch(() => {
          if (!ctrl.signal.aborted) setOutlines((m) => new Map(m).set(key, null));
        });
    }
    return () => ctrl.abort();
  }, [client, circles]);
  return outlines;
}

export function ZonesMap({ zones, selectedId, onSelect, children, testId = "zones-map" }: { zones: readonly ZoneVersion[]; selectedId?: string | null; onSelect?(id: string): void; children?: ReactNode; testId?: string }) {
  const t = useT();
  const { lang } = useLang();
  const { resolved } = useTheme();
  const cfg = useRuntimeConfig();
  const origin = useSyncExternalStore(
    noSubscribe,
    () => window.location.origin,
    () => null,
  );
  const outlines = useCircleOutlines(useConsole(), zones);
  const { views, undrawn } = useMemo(() => zoneViews(zones, lang, outlines), [zones, lang, outlines]);
  const counts = useMemo(() => {
    const c: Partial<Record<ZoneType, number>> = {};
    for (const z of views) c[z.type] = (c[z.type] ?? 0) + 1;
    return c;
  }, [views]);
  return (
    <div className="flex flex-col gap-1" data-testid={testId}>
      {undrawn.length > 0 && (
        <p role="status" className="m-0 text-xs" data-testid={`${testId}-undrawn`}>
          {t("authority.zones.undrawn", { ids: undrawn.join(", ") })}
        </p>
      )}
      <div className="relative h-[45vh] min-h-64">
        {cfg.mapView === null ? (
          <p role="alert" className="p-4 text-[var(--us-danger)]" data-testid="map-not-configured">
            {t("authority.map.not_configured", { problem: cfg.mapViewProblem ?? "" })}
          </p>
        ) : (
          origin !== null && (
            <MapView
              className="absolute inset-0"
              basemap={{ baseUrl: origin }}
              initial={{ center: cfg.mapView.center, zoom: cfg.mapView.zoom, bearing: 0, pitch: 0 }}
              lang={lang}
              scheme={resolved}
            >
              <ZoneLayer id="authoring-zones" zones={views} selectedId={selectedId ?? null} {...(onSelect === undefined ? {} : { onSelect })} />
              {children}
            </MapView>
          )
        )}
      </div>
      <ZoneLegend counts={counts} />
    </div>
  );
}
