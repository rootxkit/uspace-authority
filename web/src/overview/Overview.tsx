"use client";

// /<locale> (every console session): the overview. The key figures and
// panels are only what the console already reads: the live picture
// (tracks, active violations and sources from picture-ws, for the
// configured map view) and, through the BFF, the published zones, the
// work queues a role's reads admit (violations awaiting review, open
// incidents, reports to classify) and api's counts of the registry, the
// U-space airspaces, the certificates and the audit log's last 24 hours
// (/v1/overview/*, each read only by the roles of its list). A figure a
// role does not read is
// not shown; one that was refused or failed is a dash with the reason,
// never a zero (E-02). A queue read is one page: past it the figure says
// "at least". Nothing here judges: every status repeats what api or
// picture-ws said, in words.
import Link from "next/link";
import { useCallback, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "@rootxkit/uspace-ui/auth/client";
import { AlertList } from "@rootxkit/uspace-ui/alerts";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { TrackLayer, ZoneLayer } from "@rootxkit/uspace-ui/layers";
import { TrackLegend, ZoneLegend } from "@rootxkit/uspace-ui/legend";
import { subscribeFrame, useNowMs } from "@rootxkit/uspace-ui/live";
import { MapControls, MapView, type BBox, type LayerToggle } from "@rootxkit/uspace-ui/map";
import type { Trust, ZoneType } from "@rootxkit/uspace-ui/model";
import { SourcesPanel } from "@rootxkit/uspace-ui/status";
import { SEVERITY_KEYS } from "@rootxkit/uspace-ui/symbology";
import { useTheme, type StatusTone } from "@rootxkit/uspace-ui/theme";
import { Button, EmptyState, KpiRow, MapPanel, PageHeader, Panel, StatTile, StatusBadge } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { useRuntimeConfig } from "../components/Providers";
import { LoadNotice } from "../common/Problem";
import { must, useLoad, type Load } from "../common/useApi";
import { isUnverifiedClaim } from "../picture/adapt";
import { headerNowMs } from "../picture/feedAge";
import { StatusLine } from "../picture/StatusLine";
import { BBoxWatcher } from "../picture/InspectorMap";
import { SUBSCRIBE_LAYERS, TRAIL_POINTS, usePicture } from "../picture/usePicture";
import { useReportFeed } from "../shell/feedPill";
import { AuditIcon, CertificateIcon, IncidentIcon, OccurrenceIcon, RegistryIcon, SourceIcon, TrackIcon, USpaceIcon, ViolationIcon, ZoneIcon } from "../shell/icons";
import { renderLink } from "../shell/link";
import type { Role } from "../shell/nav";
import { consolePath, loginPath, picturePath } from "../shell/paths";
import { useZones } from "../zones/useZones";
import {
  CERTIFICATE_STATUSES,
  REGISTRY_STATUSES,
  ZONE_STATES,
  countSummary,
  queueCount,
  sourceSummary,
  type CountSummary,
  type QueueCount,
} from "./figures";

type S = components["schemas"];

/** One page of a queue: api's largest. A display bound: past it the figure says "at least". */
export const QUEUE_PAGE_LIMIT = 200;
/** Rows of a queue the overview lists; the page has the rest. A display bound. */
export const QUEUE_ROWS_SHOWN = 5;
/** How often ages are redrawn. Display-only. */
const TICK_MS = 1000;

/** The roles each queue's read admits (api/openapi.yaml x-roles), as the console offers them. */
export const QUEUE_ROLES = {
  violations: ["inspector"],
  incidents: ["inspector", "incident_officer"],
  // The occurrence reports are the incident officer's alone (src/shell/nav-oversight.ts).
  occurrences: ["incident_officer"],
  zones: ["inspector", "admin", "viewer"],
} as const satisfies Record<string, readonly Role[]>;

/**
 * The roles each count's read admits (api/openapi.yaml x-roles of
 * /v1/overview/*): the roles of its domain's list, as the console offers
 * them. summary-roles.test.ts holds the two together.
 */
export const SUMMARY_ROLES = {
  registry: ["registrar", "inspector", "viewer"],
  uspace: ["admin"],
  certificates: ["admin"],
  audit: ["admin", "auditor"],
} as const satisfies Record<string, readonly Role[]>;

/** The catalogue key of each status a count names (the contract's enums). */
const REGISTRY_STATUS_KEYS = {
  active: "authority.registry.status.active",
  suspended: "authority.registry.status.suspended",
  revoked: "authority.registry.status.revoked",
  expired: "authority.registry.status.expired",
} as const satisfies Record<S["RegistryStatus"], string>;
const ZONE_STATE_KEYS = {
  draft: "authority.zone.state.draft",
  approved: "authority.zone.state.approved",
  published: "authority.zone.state.published",
  superseded: "authority.zone.state.superseded",
} as const satisfies Record<S["ZoneState"], string>;
const CERTIFICATE_STATUS_KEYS = {
  issued: "authority.cert.status.issued",
  operating: "authority.cert.status.operating",
  ceased: "authority.cert.status.ceased",
  suspended: "authority.cert.status.suspended",
  limited: "authority.cert.status.limited",
  revoked: "authority.cert.status.revoked",
  lapsed: "authority.cert.status.lapsed",
} as const satisfies Record<S["CertificateStatus"], string>;

const SEVERITY_TONE = { info: "info", warning: "warning", critical: "critical" } as const satisfies Record<S["ViolationSummary"]["severity"], StatusTone>;

function hasAny(roles: readonly string[], admitted: readonly Role[]): boolean {
  return admitted.some((r) => roles.includes(r));
}

function noSubscribe(): () => void {
  return () => undefined;
}

/** A queue read's state as its figure's. */
function countOf<T>(q: Load<{ rows: readonly T[]; count: QueueCount }>): Load<QueueCount> {
  return q.kind === "loaded" ? { kind: "loaded", data: q.data.count } : q;
}

/** A queue's figure: the count, "at least" past one page, a dash with the reason while it is not known. */
function QueueTile(props: { label: string; icon: ReactNode; state: Load<QueueCount>; href: string; testId: string; pendingKey: string }) {
  const t = useT();
  const s = props.state;
  const known = s.kind === "loaded" ? s.data : null;
  const value = known === null ? null : known.more ? t("authority.overview.at_least", { count: known.count }) : known.count;
  const hint =
    s.kind === "refused"
      ? t("authority.overview.refused", { status: s.error.status })
      : s.kind === "failed"
        ? t("authority.overview.failed")
        : s.kind === "loaded"
          ? undefined
          : t("authority.overview.loading");
  return (
    <div data-testid={props.testId} data-state={s.kind} data-count={known?.count} className="grid">
      <StatTile
        icon={props.icon}
        label={props.label}
        value={value}
        {...(known === null
          ? {}
          : { status: known.count === 0 ? { tone: "ok" as const, label: t("authority.overview.none") } : { tone: "warning" as const, label: t(props.pendingKey) } })}
        hint={
          hint ?? (
            <Link className="underline underline-offset-2" href={props.href}>
              {t("authority.overview.open_page")}
            </Link>
          )
        }
      />
    </div>
  );
}

/** A read's state through f once it has loaded. */
function mapLoad<T, U>(l: Load<T>, f: (data: T) => U): Load<U> {
  return l.kind === "loaded" ? { kind: "loaded", data: f(l.data) } : l;
}

/**
 * One of api's counts: the total (or "at least" past a bound), the
 * statuses it counted, each in words, and the database clock's time of
 * the count; a dash with the reason while it is not known (E-02).
 */
function CountTile(props: {
  label: string;
  icon: ReactNode;
  state: Load<CountSummary>;
  /** The catalogue key of each status's name; none for a count without statuses. */
  statusKeys?: Readonly<Record<string, string>>;
  /** The key of the time line: when it was counted, or the window it counts. */
  timeKey: string;
  href: string;
  testId: string;
}) {
  const t = useT();
  const { lang } = useLang();
  const s = props.state;
  const known = s.kind === "loaded" ? s.data : null;
  const value = known === null ? null : known.more ? t("authority.overview.at_least", { count: known.count }) : known.count;
  let hint: ReactNode;
  if (s.kind === "refused") hint = t("authority.overview.refused", { status: s.error.status });
  else if (s.kind === "failed") hint = t("authority.overview.failed");
  else if (known === null) hint = t("authority.overview.loading");
  else {
    const keys = props.statusKeys;
    hint = (
      <span className="grid gap-0.5">
        {keys !== undefined && (
          <span data-testid={`${props.testId}-breakdown`} className="flex flex-wrap gap-x-2">
            {known.items.length === 0 ? (
              <span>{t("authority.overview.breakdown_none")}</span>
            ) : (
              known.items.map((i) => (
                <span key={i.status} data-status={i.status} data-count={i.count}>
                  {t("authority.overview.breakdown_item", { status: t(keys[i.status] ?? i.status), count: i.count })}
                </span>
              ))
            )}
          </span>
        )}
        <span>{t(props.timeKey, { time: fmtTimeUTC(known.asOf, lang) })}</span>
        <Link className="underline underline-offset-2" href={props.href}>
          {t("authority.overview.open_page")}
        </Link>
      </span>
    );
  }
  return (
    <div data-testid={props.testId} data-state={s.kind} data-count={known?.count} data-more={known === null ? undefined : String(known.more)} className="grid">
      <StatTile icon={props.icon} label={props.label} value={value} hint={hint} />
    </div>
  );
}

/** A queue's first rows, each a link to its page, or what api said instead. */
function QueueList<T>(props: {
  titleKey: string;
  state: Load<{ rows: readonly T[]; count: QueueCount }>;
  row(r: T): { id: string; href: string; label: string; meta: string; tone: StatusTone; badge: string };
  emptyKey: string;
  allHref: string;
  testId: string;
}) {
  const t = useT();
  const s = props.state;
  return (
    <Panel
      title={t(props.titleKey)}
      data-testid={props.testId}
      padding="none"
      actions={
        <Button asChild variant="outline" size="sm">
          <Link href={props.allHref}>{t("authority.overview.see_all")}</Link>
        </Button>
      }
    >
      {s.kind !== "loaded" ? (
        <div className="p-4">
          <LoadNotice state={s} />
        </div>
      ) : s.data.rows.length === 0 ? (
        <EmptyState title={t(props.emptyKey)} />
      ) : (
        <ul className="m-0 grid list-none p-0">
          {s.data.rows.slice(0, QUEUE_ROWS_SHOWN).map((r) => {
            const v = props.row(r);
            return (
              <li key={v.id} className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-border px-4 py-2.5 text-sm last:border-b-0">
                <span className="grid min-w-0 gap-0.5">
                  <Link className="truncate font-semibold underline-offset-2 hover:underline" href={v.href}>
                    {v.label}
                  </Link>
                  <span className="text-xs text-muted-foreground tabular-nums">{v.meta}</span>
                </span>
                <StatusBadge tone={v.tone}>{v.badge}</StatusBadge>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

export function Overview() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const cfg = useRuntimeConfig();
  const { session } = useSession();
  const { resolved } = useTheme();
  const roles = session?.roles ?? [];
  const toLogin = useCallback(() => router.replace(loginPath(lang)), [router, lang]);
  const picture = usePicture(toLogin);
  const { feed } = picture;
  const nowMs = useNowMs(TICK_MS);
  useReportFeed(feed, nowMs);
  const readsZones = hasAny(roles, QUEUE_ROLES.zones);
  const zones = useZones(lang);
  const [showTracks, setShowTracks] = useState(true);
  const [showZones, setShowZones] = useState(true);
  const origin = useSyncExternalStore(
    noSubscribe,
    () => window.location.origin,
    () => null,
  );
  const send = feed.send;
  const onBBox = useCallback((b: BBox) => send(subscribeFrame([b.minLng, b.minLat, b.maxLng, b.maxLat], SUBSCRIBE_LAYERS)), [send]);

  const violationsQ = useLoad(hasAny(roles, QUEUE_ROLES.violations) ? "overview:violations" : null, async (c) => {
    const page = must(await c.GET("/v1/violations", { params: { query: { status: "new", limit: QUEUE_PAGE_LIMIT } } }));
    return { rows: page.violations, count: queueCount(page.violations, page.next_cursor) };
  });
  const incidentsQ = useLoad(hasAny(roles, QUEUE_ROLES.incidents) ? "overview:incidents" : null, async (c) => {
    const page = must(await c.GET("/v1/incidents", { params: { query: { status: "open", limit: QUEUE_PAGE_LIMIT } } }));
    return { rows: page.incidents, count: queueCount(page.incidents, page.next_cursor) };
  });
  const occurrencesQ = useLoad(hasAny(roles, QUEUE_ROLES.occurrences) ? "overview:occurrences" : null, async (c) => {
    const page = must(await c.GET("/v1/occurrences", { params: { query: { state: "received", limit: QUEUE_PAGE_LIMIT } } }));
    return { rows: page.occurrences, count: queueCount(page.occurrences, page.next_cursor) };
  });

  // api's counts, each read only by the roles its operation admits.
  const registryQ = useLoad(hasAny(roles, SUMMARY_ROLES.registry) ? "overview:registry" : null, async (c) => must(await c.GET("/v1/overview/registry")));
  const uspaceQ = useLoad(hasAny(roles, SUMMARY_ROLES.uspace) ? "overview:uspace" : null, async (c) => {
    const r = must(await c.GET("/v1/overview/uspace"));
    return countSummary(r, ZONE_STATES, r.as_of);
  });
  const certificatesQ = useLoad(hasAny(roles, SUMMARY_ROLES.certificates) ? "overview:certificates" : null, async (c) => {
    const r = must(await c.GET("/v1/overview/certificates"));
    return countSummary(r, CERTIFICATE_STATUSES, r.as_of);
  });
  const auditQ = useLoad(hasAny(roles, SUMMARY_ROLES.audit) ? "overview:audit" : null, async (c) => {
    const r = must(await c.GET("/v1/overview/audit"));
    return { count: r.events, more: r.more, items: [], asOf: r.as_of } satisfies CountSummary;
  });
  const operatorsS = mapLoad(registryQ.state, (r) => countSummary(r.operators, REGISTRY_STATUSES, r.as_of));
  const uasS = mapLoad(registryQ.state, (r) => countSummary(r.uas, REGISTRY_STATUSES, r.as_of));
  const pilotsS = mapLoad(registryQ.state, (r) => countSummary(r.pilots, REGISTRY_STATUSES, r.as_of));

  const tracks = useMemo(() => [...picture.tracks.values()], [picture.tracks]);
  const active = useMemo(
    () => [...picture.alerts.values()].filter((a) => a.state !== "cleared").sort((a, b) => b.raisedAt.localeCompare(a.raisedAt) || a.alertId.localeCompare(b.alertId)),
    [picture.alerts],
  );
  const unverified = tracks.filter(isUnverifiedClaim).length;
  const trustCounts = useMemo(() => {
    const c: Partial<Record<Trust, number>> = {};
    for (const tr of tracks) c[tr.trust] = (c[tr.trust] ?? 0) + 1;
    return c;
  }, [tracks]);
  const zoneViews = useMemo(() => (zones.kind === "loaded" ? zones.zones : []), [zones]);
  const zoneCounts = useMemo(() => {
    const c: Partial<Record<ZoneType, number>> = {};
    for (const z of zoneViews) c[z.type] = (c[z.type] ?? 0) + 1;
    return c;
  }, [zoneViews]);
  const src = sourceSummary(picture.sources);
  // The picture's figures are known once picture-ws has said something on this connection.
  const pictureKnown = feed.lastFrameAtMs !== null;
  const asOf = feed.lastFrameAtMs === null ? t("authority.overview.no_frame") : t("authority.overview.as_of", { time: fmtTimeUTC(new Date(feed.lastFrameAtMs).toISOString(), lang, { seconds: true }) });
  const toggles: LayerToggle[] = [
    { id: "tracks", labelKey: "authority.layer.tracks", visible: showTracks, onChange: setShowTracks },
    { id: "zones", labelKey: "authority.layer.zones", visible: showZones, onChange: setShowZones },
  ];

  return (
    <div className="mx-auto grid w-full max-w-[96rem] gap-6 px-4 py-5 sm:px-6" data-testid="overview">
      <PageHeader
        breadcrumbs={[{ label: t("authority.nav.group.operations") }, { label: t("authority.nav.overview") }]}
        renderLink={renderLink}
        title={t("authority.overview.title")}
        description={t("authority.overview.intro")}
        actions={
          <Button asChild variant="outline" size="sm">
            <Link href={picturePath(lang)}>{t("authority.overview.open_picture")}</Link>
          </Button>
        }
      />

      <KpiRow label={t("authority.overview.kpis")}>
        <div data-testid="kpi-tracks" data-count={pictureKnown ? tracks.length : undefined} className="grid">
          <StatTile
            icon={<TrackIcon />}
            label={t("authority.overview.tracks")}
            value={pictureKnown ? tracks.length : null}
            {...(pictureKnown && unverified > 0 ? { status: { tone: "info" as const, label: t("authority.overview.tracks_unverified", { count: unverified }) } } : {})}
            hint={asOf}
          />
        </div>
        <div data-testid="kpi-active-violations" data-count={pictureKnown ? active.length : undefined} className="grid">
          <StatTile
            icon={<ViolationIcon />}
            label={t("authority.overview.active_violations")}
            value={pictureKnown ? active.length : null}
            {...(pictureKnown
              ? { status: active.length === 0 ? { tone: "ok" as const, label: t("authority.overview.none_active") } : { tone: "critical" as const, label: t("authority.overview.active") } }
              : {})}
            hint={asOf}
          />
        </div>
        <div data-testid="kpi-sources" data-healthy={pictureKnown ? src.healthy : undefined} className="grid">
          <StatTile
            icon={<SourceIcon />}
            label={t("authority.overview.sources")}
            value={pictureKnown && src.total > 0 ? t("authority.overview.sources_value", { healthy: src.healthy, total: src.total }) : null}
            {...(pictureKnown && src.total > 0
              ? {
                  status:
                    src.attention === 0
                      ? { tone: "ok" as const, label: t("authority.overview.sources_ok", { disabled: src.disabled }) }
                      : { tone: "warning" as const, label: t("authority.overview.sources_attention", { count: src.attention }) },
                }
              : {})}
            hint={pictureKnown && src.total === 0 ? t("authority.overview.sources_none") : asOf}
          />
        </div>
        {readsZones && (
          <div data-testid="kpi-zones" data-state={zones.kind} className="grid">
            <StatTile
              icon={<ZoneIcon />}
              label={t("authority.overview.zones")}
              value={
                zones.kind === "loaded"
                  ? zones.truncated
                    ? t("authority.overview.at_least", { count: zones.zones.length + zones.undrawn.length })
                    : zones.zones.length + zones.undrawn.length
                  : null
              }
              hint={
                zones.kind === "refused"
                  ? t("authority.overview.refused", { status: zones.status })
                  : zones.kind === "failed"
                    ? t("authority.overview.failed")
                    : zones.kind === "loading"
                      ? t("authority.overview.loading")
                      : t("authority.overview.zones_hint")
              }
            />
          </div>
        )}
        {violationsQ.state.kind !== "idle" && (
          <QueueTile
            testId="kpi-review"
            icon={<ViolationIcon />}
            label={t("authority.overview.review")}
            state={countOf(violationsQ.state)}
            href={consolePath(lang, "/violations")}
            pendingKey="authority.overview.review_pending"
          />
        )}
        {incidentsQ.state.kind !== "idle" && (
          <QueueTile
            testId="kpi-incidents"
            icon={<IncidentIcon />}
            label={t("authority.overview.incidents")}
            state={countOf(incidentsQ.state)}
            href={consolePath(lang, "/incidents")}
            pendingKey="authority.overview.incidents_pending"
          />
        )}
        {registryQ.state.kind !== "idle" && (
          <>
            <CountTile
              testId="kpi-operators"
              icon={<RegistryIcon />}
              label={t("authority.overview.operators")}
              state={operatorsS}
              statusKeys={REGISTRY_STATUS_KEYS}
              timeKey="authority.overview.counted_at"
              href={consolePath(lang, "/registry/operators")}
            />
            <CountTile
              testId="kpi-uas"
              icon={<RegistryIcon />}
              label={t("authority.overview.uas")}
              state={uasS}
              statusKeys={REGISTRY_STATUS_KEYS}
              timeKey="authority.overview.counted_at"
              href={consolePath(lang, "/registry/uas")}
            />
            <CountTile
              testId="kpi-pilots"
              icon={<RegistryIcon />}
              label={t("authority.overview.pilots")}
              state={pilotsS}
              statusKeys={REGISTRY_STATUS_KEYS}
              timeKey="authority.overview.counted_at"
              href={consolePath(lang, "/registry/pilots")}
            />
          </>
        )}
        {uspaceQ.state.kind !== "idle" && (
          <CountTile
            testId="kpi-uspace"
            icon={<USpaceIcon />}
            label={t("authority.overview.uspace")}
            state={uspaceQ.state}
            statusKeys={ZONE_STATE_KEYS}
            timeKey="authority.overview.counted_at"
            href={consolePath(lang, "/uspace")}
          />
        )}
        {certificatesQ.state.kind !== "idle" && (
          <CountTile
            testId="kpi-certificates"
            icon={<CertificateIcon />}
            label={t("authority.overview.certificates")}
            state={certificatesQ.state}
            statusKeys={CERTIFICATE_STATUS_KEYS}
            timeKey="authority.overview.counted_at"
            href={consolePath(lang, "/certificates")}
          />
        )}
        {auditQ.state.kind !== "idle" && (
          <CountTile
            testId="kpi-audit"
            icon={<AuditIcon />}
            label={t("authority.overview.audit")}
            state={auditQ.state}
            timeKey="authority.overview.audit_window"
            href={consolePath(lang, "/audit")}
          />
        )}
        {occurrencesQ.state.kind !== "idle" && (
          <QueueTile
            testId="kpi-occurrences"
            icon={<OccurrenceIcon />}
            label={t("authority.overview.occurrences")}
            state={countOf(occurrencesQ.state)}
            href={consolePath(lang, "/occurrences")}
            pendingKey="authority.overview.occurrences_pending"
          />
        )}
      </KpiRow>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_26rem]">
        <MapPanel
          title={t("authority.overview.map_title")}
          description={t("authority.overview.map_description")}
          legend={
            <div className="grid gap-2">
              <TrackLegend counts={trustCounts} />
              <ZoneLegend counts={zoneCounts} />
            </div>
          }
          defaultLegendOpen={false}
          mapClassName="h-[26rem]"
          actions={
            <Button asChild variant="outline" size="sm">
              <Link href={picturePath(lang)}>{t("authority.overview.open_picture")}</Link>
            </Button>
          }
        >
          <div className="absolute inset-0">
            {cfg.mapView === null ? (
              <p role="alert" className="m-0 p-4 text-sm text-[var(--us-danger)]" data-testid="map-not-configured">
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
                  <ZoneLayer id="overview-zones" zones={zoneViews} visible={showZones} />
                  {feed.staleAfterS !== null && (
                    <TrackLayer tracks={tracks} staleAfterS={feed.staleAfterS} nowMs={nowMs} trails={{ points: TRAIL_POINTS }} visible={showTracks} />
                  )}
                  <MapControls layers={toggles} />
                </MapView>
              )
            )}
          </div>
        </MapPanel>
        <Panel
          title={t("authority.overview.alerts_title")}
          description={t("authority.overview.alerts_description")}
          data-testid="overview-alerts"
          actions={
            pictureKnown ? (
              active.length === 0 ? (
                <StatusBadge tone="ok">{t("authority.overview.none_active")}</StatusBadge>
              ) : (
                <StatusBadge tone="critical">{t("authority.overview.active_count", { count: active.length })}</StatusBadge>
              )
            ) : undefined
          }
        >
          <AlertList alerts={active} tracks={picture.tracks} nowMs={nowMs} canAcknowledge={false} />
        </Panel>
      </div>

      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_26rem]">
        <div className="grid content-start gap-6">
          {violationsQ.state.kind !== "idle" && (
            <QueueList<S["ViolationSummary"]>
              testId="overview-review"
              titleKey="authority.overview.review_title"
              state={violationsQ.state}
              emptyKey="authority.overview.review_none"
              allHref={consolePath(lang, "/violations")}
              row={(v) => ({
                id: v.violation_id,
                href: consolePath(lang, `/violations/${v.violation_id}`),
                label: t(`authority.violation.kind.${v.kind}`),
                meta: t("authority.overview.opened_at", { at: fmtTimeUTC(v.opened_at, lang) }),
                tone: SEVERITY_TONE[v.severity],
                badge: t(SEVERITY_KEYS[v.severity]),
              })}
            />
          )}
          {incidentsQ.state.kind !== "idle" && (
            <QueueList<S["IncidentSummary"]>
              testId="overview-incidents"
              titleKey="authority.overview.incidents_title"
              state={incidentsQ.state}
              emptyKey="authority.overview.incidents_none"
              allHref={consolePath(lang, "/incidents")}
              row={(i) => ({
                id: i.incident_id,
                href: consolePath(lang, `/incidents/${i.incident_id}`),
                label: t(`authority.incident.kind.${i.kind}`),
                meta: t("authority.overview.occurred_at", { at: fmtTimeUTC(i.occurred_at, lang) }),
                tone: SEVERITY_TONE[i.severity],
                badge: t(SEVERITY_KEYS[i.severity]),
              })}
            />
          )}
          {occurrencesQ.state.kind !== "idle" && (
            <QueueList<S["OccurrenceSummary"]>
              testId="overview-occurrences"
              titleKey="authority.overview.occurrences_title"
              state={occurrencesQ.state}
              emptyKey="authority.overview.occurrences_none"
              allHref={consolePath(lang, "/occurrences")}
              row={(o) => ({
                id: o.occurrence_id,
                href: consolePath(lang, `/occurrences/${o.occurrence_id}`),
                label: t(`authority.occurrence.category.${o.category}`),
                meta: t("authority.overview.received_at", { at: fmtTimeUTC(o.received_at, lang) }),
                tone: o.within_72h ? "info" : "warning",
                badge: t(o.within_72h ? "authority.occurrences.within_72h" : "authority.occurrences.late"),
              })}
            />
          )}
          {violationsQ.state.kind === "idle" && incidentsQ.state.kind === "idle" && occurrencesQ.state.kind === "idle" && (
            <Panel title={t("authority.overview.queues_title")}>
              <EmptyState title={t("authority.overview.queues_none")} description={t("authority.overview.queues_none_detail")} />
            </Panel>
          )}
        </div>
        {/* The kit's SourcesPanel is a panel of its own, with its heading. */}
        <div className="grid content-start gap-3" data-testid="overview-sources">
          <SourcesPanel sources={picture.sources} nowMs={nowMs} canSwitch={false} />
          <StatusLine status={feed} nowMs={headerNowMs(nowMs, feed.lastFrameAtMs)} />
        </div>
      </div>
    </div>
  );
}
