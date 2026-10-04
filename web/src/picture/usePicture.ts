"use client";

// The picture feed (docs/runbooks/picture.md): the kit's live client on
// /v1/picture/ws, same-origin, the session cookie on the upgrade (M22).
// Status frames fill the feed status and the source store; snapshots
// replace the track and alert stores (C-08: the active violations on
// connect); every other frame comes here and goes to its store through
// the adapter. A 4401 close is "sign in again".
//
// The thresholds (stale_after_s, live_max_age_s) are the status frame's,
// and nothing here has a default for them (INV-03): until one arrives the
// map draws no age bucket and says so.
import { useEffect, useState } from "react";
import {
  ALERT_STORE_LIMIT,
  createAlertStore,
  createSourceStore,
  createTrackStore,
  useFeed,
  useStore,
  type ConsoleFrame,
  type LiveFeed,
} from "@rootxkit/uspace-ui/live";
import type { AlertView, TrackView } from "@rootxkit/uspace-ui/model";
import type { components } from "../api/types";
import { PICTURE_SOURCES_PATH, PICTURE_WS_PATH } from "../runtime";
import { SOURCE_STATUS_SCHEMA, TRACK_SCHEMA, VIOLATION_SCHEMA, adaptTrack, adaptViolation, type AdaptedViolation, type TrackExtras } from "./adapt";
import { createKeyedStore, followKeys, type KeyedStore } from "./keyed";

/**
 * Tracks this console holds; past it the least recently updated is
 * evicted and counted (E-10). A display bound, the same as picture-ws's
 * default PICTURE_MAX_TRACKS order of magnitude; not a threshold.
 */
export const MAX_TRACKS = 5000;
/** Trail points kept per track. A display bound. */
export const TRAIL_POINTS = 30;
/** How often the console asks picture-ws when the bus was lost, while it is lost. Display-only. */
export const NATS_SINCE_POLL_MS = 15_000;

/** The layers the console subscribes to. Manned traffic is not drawn on this map yet (the page says so). */
export const SUBSCRIBE_LAYERS = ["tracks", "alerts", "zones"] as const;

/** A track's extras and when this console received them. */
export interface HeldExtras extends TrackExtras {
  receivedAtMs: number;
}

/** What the console counted and did not show, by cause: nothing is dropped silently. */
export interface PictureCounters {
  tracksRefused: number;
  violationsRefused: number;
  /** Frames of a schema this map does not draw (source/status/v1 is applied by the status frame). */
  framesNotShown: number;
}

export interface Picture {
  feed: LiveFeed;
  tracks: ReadonlyMap<string, TrackView>;
  extras: ReadonlyMap<string, HeldExtras>;
  alerts: ReadonlyMap<string, AlertView>;
  violations: ReadonlyMap<string, AdaptedViolation>;
  sources: ReturnType<ReturnType<typeof createSourceStore>["snapshot"]>;
  counters: PictureCounters;
  tracksEvicted: number;
  /** picture-ws's nats_since while the bus is lost; null otherwise or not known yet. */
  natsSince: string | null;
}

interface Stores {
  tracks: ReturnType<typeof createTrackStore>;
  alerts: ReturnType<typeof createAlertStore>;
  sources: ReturnType<typeof createSourceStore>;
  extras: KeyedStore<HeldExtras>;
  violations: KeyedStore<AdaptedViolation>;
}

function makeStores(): Stores {
  return {
    tracks: createTrackStore({ trailPoints: TRAIL_POINTS, maxTracks: MAX_TRACKS }),
    alerts: createAlertStore(),
    sources: createSourceStore(),
    extras: createKeyedStore<HeldExtras>(MAX_TRACKS),
    violations: createKeyedStore<AdaptedViolation>(ALERT_STORE_LIMIT),
  };
}

type PictureSources = components["schemas"]["PictureSources"];

/** picture-ws's nats_since while the status says the bus is lost (GET /v1/picture/sources). */
function useNatsSince(lost: boolean): string | null {
  const [since, setSince] = useState<string | null>(null);
  useEffect(() => {
    if (!lost) return;
    let live = true;
    const read = () => {
      fetch(PICTURE_SOURCES_PATH, { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(async (res) => {
          if (!res.ok) return;
          const body = (await res.json()) as Partial<PictureSources>;
          if (live && typeof body.nats_since === "string") setSince(body.nats_since);
        })
        .catch(() => undefined);
    };
    read();
    const id = setInterval(read, NATS_SINCE_POLL_MS);
    return () => {
      live = false;
      clearInterval(id);
      setSince(null);
    };
  }, [lost]);
  return lost ? since : null;
}

export function usePicture(onUnauthorized: () => void): Picture {
  const [stores] = useState(makeStores);
  const [counters, setCounters] = useState<PictureCounters>({ tracksRefused: 0, violationsRefused: 0, framesNotShown: 0 });
  useEffect(() => () => stores.alerts.dispose(), [stores]);
  // A violation's members are kept while the kit holds its alert: a
  // cleared alert dropped at the end of its hold, or one a snapshot left
  // out, takes them with it.
  useEffect(() => followKeys(stores.alerts, stores.violations), [stores]);

  const bump = (k: keyof PictureCounters) => setCounters((c) => ({ ...c, [k]: c[k] + 1 }));

  const holdTrack = (f: ConsoleFrame) => {
    const a = adaptTrack(f);
    if (a === null) {
      bump("tracksRefused");
      return null;
    }
    stores.extras.set(a.view.trackId, { ...a.extras, receivedAtMs: Date.now() });
    return a.view;
  };
  const holdViolation = (f: ConsoleFrame) => {
    const v = adaptViolation(f);
    if (v === null) {
      bump("violationsRefused");
      return null;
    }
    stores.violations.set(v.alert.alertId, v);
    return v.alert;
  };

  const feed = useFeed({
    url: PICTURE_WS_PATH,
    onUnauthorized,
    stores: {
      sources: stores.sources,
      tracks: { store: stores.tracks, adapt: holdTrack },
      alerts: { store: stores.alerts, adapt: holdViolation },
    },
    onFrame(f) {
      if (f.schema === TRACK_SCHEMA) {
        const view = holdTrack(f);
        if (view !== null) stores.tracks.upsert(view);
      } else if (f.schema === VIOLATION_SCHEMA) {
        const alert = holdViolation(f);
        if (alert !== null) stores.alerts.apply(alert);
      } else if (f.schema !== SOURCE_STATUS_SCHEMA) {
        // source/status/v1 changes reach the panel with the next status
        // frame (every 2 s), which carries every source.
        bump("framesNotShown");
      }
    },
  });

  const tracks = useStore(stores.tracks);
  const alerts = useStore(stores.alerts);
  const sources = useStore(stores.sources);
  const extras = useStore(stores.extras);
  const violations = useStore(stores.violations);
  // A snapshot replaced the tracks: keep only the extras of tracks still held.
  useEffect(() => stores.extras.retain(new Set(tracks.keys())), [stores, tracks]);
  // Read on every render: an eviction comes with a store change, which renders.
  const tracksEvicted = stores.tracks.counters().track_evicted;
  const lost = feed.degraded.includes("nats_unavailable") || feed.extras.nats === "unavailable";
  const natsSince = useNatsSince(lost && feed.connection === "live");
  return { feed, tracks, extras, alerts, violations, sources, counters, tracksEvicted, natsSince };
}
