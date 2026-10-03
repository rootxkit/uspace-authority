"use client";

// The inspector map (WP-21): MapLibre from uspace-ui with the zone and
// track symbology, the /v1/picture/ws subscription driven by the
// viewport, the tracks with their trust class, identification and age,
// the sources, the active violations, and every degraded state said in
// words. It renders and judges nothing: no age bucket, threshold,
// identification or geometry is computed here.
import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { AgeLegend, IdentificationLegend, TrackLegend, ZoneLegend } from "@rootxkit/uspace-ui/legend";
import { TrackLayer, ZoneLayer } from "@rootxkit/uspace-ui/layers";
import { subscribeFrame, useNowMs } from "@rootxkit/uspace-ui/live";
import { MapControls, MapView, subscriptionBBox, useBBoxSubscription, useMapContext, type BBox, type LayerToggle } from "@rootxkit/uspace-ui/map";
import type { Trust, ZoneType } from "@rootxkit/uspace-ui/model";
import { FeedStatusBar, FrozenOverlay, SourcesPanel } from "@rootxkit/uspace-ui/status";
import { identDrawn, type IdentKey } from "@rootxkit/uspace-ui/symbology";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { useRuntimeConfig } from "../components/Providers";
import { loginPath } from "../shell/paths";
import { useZones } from "../zones/useZones";
import { DegradedBanner, FeedFacts, TrackDetail, TrackList, ViolationsPanel } from "./panels";
import { SUBSCRIBE_LAYERS, TRAIL_POINTS, usePicture } from "./usePicture";

/**
 * How the visible box becomes the subscription (spec 05 §3, §5): padded
 * by a quarter of the view, widened to a 0.1° grid (the c5 cell) so a
 * small pan subscribes to nothing new, sent 300 ms after the map settles.
 * Display-only; picture-ws adds its own ring of neighbour cells.
 */
export const BBOX_MARGIN_FRACTION = 0.25;
export const BBOX_QUANTIZE_DEG = 0.1;
export const BBOX_DEBOUNCE_MS = 300;
/** How often ages are redrawn. Display-only. */
const TICK_MS = 1000;

/**
 * Calls `onChange` with the padded, quantised bbox of the enclosing
 * MapView: the initial view's at once (before the map loads, and when
 * the browser has no WebGL, so the picture still arrives in the lists),
 * then the map's on load and after every settled move.
 */
function BBoxWatcher({ onChange }: { onChange(b: BBox): void }) {
  const { map, initialBBox } = useMapContext();
  useEffect(() => {
    if (map === null) onChange(subscriptionBBox(initialBBox, BBOX_MARGIN_FRACTION, BBOX_QUANTIZE_DEG));
  }, [map, initialBBox, onChange]);
  useBBoxSubscription({
    marginFraction: BBOX_MARGIN_FRACTION,
    quantizeDeg: BBOX_QUANTIZE_DEG,
    debounceMs: BBOX_DEBOUNCE_MS,
    onChange,
  });
  return null;
}

function noSubscribe(): () => void {
  return () => undefined;
}

export function InspectorMap() {
  const t = useT();
  const { lang } = useLang();
  const { resolved } = useTheme();
  const router = useRouter();
  const cfg = useRuntimeConfig();
  const toLogin = useCallback(() => router.replace(loginPath(lang)), [router, lang]);
  const picture = usePicture(toLogin);
  const { feed } = picture;
  const nowMs = useNowMs(TICK_MS);
  const zones = useZones(lang);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showTracks, setShowTracks] = useState(true);
  const [showZones, setShowZones] = useState(true);
  // The basemap is read from this origin's /basemap/; null while rendering on the server.
  const origin = useSyncExternalStore(
    noSubscribe,
    () => window.location.origin,
    () => null,
  );

  const send = feed.send;
  const onBBox = useCallback(
    (b: BBox) => send(subscribeFrame([b.minLng, b.minLat, b.maxLng, b.maxLat], SUBSCRIBE_LAYERS)),
    [send],
  );

  // Newest sample first; a held track is never hidden for its age.
  const tracks = useMemo(
    () => [...picture.tracks.values()].sort((a, b) => b.receivedAtMs - a.receivedAtMs || a.trackId.localeCompare(b.trackId)),
    [picture.tracks],
  );
  const active = useMemo(
    () => [...picture.alerts.values()].sort((a, b) => b.raisedAt.localeCompare(a.raisedAt) || a.alertId.localeCompare(b.alertId)),
    [picture.alerts],
  );
  const trustCounts = useMemo(() => {
    const c: Partial<Record<Trust, number>> = {};
    for (const tr of tracks) c[tr.trust] = (c[tr.trust] ?? 0) + 1;
    return c;
  }, [tracks]);
  const identCounts = useMemo(() => {
    const c: Partial<Record<IdentKey, number>> = {};
    for (const tr of tracks) {
      const k = identDrawn(tr.identification);
      c[k] = (c[k] ?? 0) + 1;
    }
    return c;
  }, [tracks]);
  const zoneViews = useMemo(() => (zones.kind === "loaded" ? zones.zones : []), [zones]);
  const zoneCounts = useMemo(() => {
    const c: Partial<Record<ZoneType, number>> = {};
    for (const z of zoneViews) c[z.type] = (c[z.type] ?? 0) + 1;
    return c;
  }, [zoneViews]);
  const selected = selectedId === null ? undefined : picture.tracks.get(selectedId);
  const toggles: LayerToggle[] = [
    { id: "tracks", labelKey: "authority.layer.tracks", visible: showTracks, onChange: setShowTracks },
    { id: "zones", labelKey: "authority.layer.zones", visible: showZones, onChange: setShowZones },
  ];

  return (
    <div className="flex flex-1 flex-col">
      <section
        aria-label={t("authority.feed.label")}
        className="flex flex-wrap items-start gap-x-6 gap-y-1 border-b border-[var(--us-border)] bg-[var(--us-surface-sunken)] px-4 py-2 text-xs"
        data-testid="feed-strip"
        data-connection={feed.connection}
      >
        <FeedStatusBar status={feed} nowMs={nowMs} />
        <FeedFacts feed={feed} counters={picture.counters} tracksEvicted={picture.tracksEvicted} trackCount={tracks.length} />
      </section>
      <DegradedBanner feed={feed} natsSince={picture.natsSince} />
      <p className="m-0 border-b border-[var(--us-border)] px-4 py-1 text-xs text-[var(--us-text-muted)]" data-testid="manned-notice">
        {t("authority.notice.manned_not_drawn")}
      </p>
      {zones.kind === "refused" && (
        <p role="status" className="m-0 border-b border-[var(--us-border)] px-4 py-1 text-xs" data-testid="zones-refused">
          {t("authority.zones.refused", { status: zones.status })}
        </p>
      )}
      {zones.kind === "failed" && (
        <p role="status" className="m-0 border-b border-[var(--us-border)] px-4 py-1 text-xs" data-testid="zones-failed">
          {t("authority.zones.failed")}
        </p>
      )}
      {zones.kind === "loaded" && (zones.undrawn.length > 0 || zones.truncated) && (
        <p role="status" className="m-0 border-b border-[var(--us-border)] px-4 py-1 text-xs" data-testid="zones-undrawn">
          {zones.truncated && t("authority.zones.truncated")} {zones.undrawn.length > 0 && t("authority.zones.undrawn", { ids: zones.undrawn.join(", ") })}
        </p>
      )}
      <div className="flex flex-1 flex-col lg:h-[75vh] lg:flex-row">
        <div className="relative h-[55vh] lg:h-auto lg:flex-1">
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
                <BBoxWatcher onChange={onBBox} />
                <ZoneLayer id="authority-zones" zones={zoneViews} visible={showZones} />
                {feed.staleAfterS !== null && (
                  <TrackLayer
                    tracks={tracks}
                    staleAfterS={feed.staleAfterS}
                    nowMs={nowMs}
                    selectedId={selectedId}
                    onSelect={setSelectedId}
                    trails={{ points: TRAIL_POINTS }}
                    visible={showTracks}
                  />
                )}
                <MapControls layers={toggles} />
              </MapView>
            )
          )}
          <FrozenOverlay status={feed} nowMs={nowMs} />
        </div>
        <aside
          aria-label={t("authority.side.label")}
          className="flex w-full flex-col gap-4 border-[var(--us-border)] p-3 lg:w-[28rem] lg:overflow-y-auto lg:border-s"
        >
          {selected !== undefined && (
            <TrackDetail track={selected} extras={picture.extras.get(selected.trackId)} nowMs={nowMs} onClose={() => setSelectedId(null)} />
          )}
          <ViolationsPanel alerts={active} violations={picture.violations} tracks={picture.tracks} onSelect={setSelectedId} />
          <section aria-label={t("authority.tracks.title")} className="flex flex-col gap-1">
            <h2 className="m-0 text-sm font-semibold">{t("authority.tracks.title")}</h2>
            <TrackList
              tracks={tracks}
              extras={picture.extras}
              nowMs={nowMs}
              staleAfterS={feed.staleAfterS}
              selectedId={selectedId}
              onSelect={setSelectedId}
            />
          </section>
          <SourcesPanel sources={picture.sources} nowMs={nowMs} canSwitch={false} />
          <TrackLegend counts={trustCounts} defaultCollapsed />
          <IdentificationLegend counts={identCounts} defaultCollapsed />
          {feed.staleAfterS !== null && <AgeLegend staleAfterS={feed.staleAfterS} defaultCollapsed />}
          <ZoneLegend counts={zoneCounts} defaultCollapsed />
        </aside>
      </div>
    </div>
  );
}
