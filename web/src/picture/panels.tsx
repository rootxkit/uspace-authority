"use client";

// The inspector map's panels: the status line, the degraded banner, the
// tracks, the selected track, the active violations. Every word is the
// catalogue's (the kit's or this app's); every number and verdict is the
// server's. Nothing here decides whether an aircraft is where it may be.
import { fmtAge, fmtAltitude, fmtHeight, fmtRegistrationNumber, fmtSpeed, fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { ageS, type LiveFeed } from "@rootxkit/uspace-ui/live";
import type { AlertView, TrackView } from "@rootxkit/uspace-ui/model";
import { AgeChip } from "@rootxkit/uspace-ui/status";
import { IDENT_REASON_KEYS, IDENT_STATUS_KEYS, SEVERITY_KEYS, TRUST_KEYS, identDrawn, identHintKey } from "@rootxkit/uspace-ui/symbology";
import { isUnverifiedClaim, type AdaptedViolation } from "./adapt";
import { degradedLines } from "./degraded";
import type { HeldExtras, PictureCounters } from "./usePicture";

/** The thresholds and counts of the feed, as the server sent them. */
export function FeedFacts(props: { feed: LiveFeed; counters: PictureCounters; tracksEvicted: number; trackCount: number }) {
  const t = useT();
  const { lang } = useLang();
  const { feed, counters } = props;
  return (
    <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs" data-testid="feed-facts">
      <dt className="text-[var(--us-text-muted)]">{t("authority.feed.thresholds")}</dt>
      <dd className="m-0" data-testid="thresholds">
        {feed.staleAfterS === null || feed.liveMaxAgeS === null
          ? t("authority.feed.no_thresholds")
          : t("authority.feed.thresholds_value", {
              stale: fmtAge(feed.staleAfterS, lang),
              live: fmtAge(feed.liveMaxAgeS, lang),
              policy: feed.policyVersion ?? "",
            })}
      </dd>
      <dt className="text-[var(--us-text-muted)]">{t("authority.feed.dropped_frames")}</dt>
      <dd className="m-0" data-testid="dropped-frames">
        {feed.connection === "live" || feed.lastStatusAtMs !== null ? feed.droppedFrames.toLocaleString(lang) : t("authority.feed.not_known")}
      </dd>
      <dt className="text-[var(--us-text-muted)]">{t("authority.feed.tracks_held")}</dt>
      <dd className="m-0" data-testid="track-count">
        {props.trackCount.toLocaleString(lang)}
      </dd>
      {(counters.tracksRefused > 0 || counters.violationsRefused > 0 || counters.framesNotShown > 0 || props.tracksEvicted > 0 || feed.framesMalformed > 0) && (
        <>
          <dt className="text-[var(--us-text-muted)]">{t("authority.feed.not_shown")}</dt>
          <dd className="m-0" data-testid="not-shown">
            {t("authority.feed.not_shown_value", {
              tracks: counters.tracksRefused,
              violations: counters.violationsRefused,
              other: counters.framesNotShown,
              evicted: props.tracksEvicted,
              malformed: feed.framesMalformed,
            })}
          </dd>
        </>
      )}
    </dl>
  );
}

/** console/status/v1's degraded[], one line each, with the server's ages and instants. */
export function DegradedBanner(props: { feed: LiveFeed; natsSince: string | null }) {
  const t = useT();
  const { lang } = useLang();
  const { feed } = props;
  const lines = degradedLines(feed.degraded, {
    natsSince: props.natsSince,
    projectionAgeS: feed.extras.projectionAgeS,
    cisAgeS: feed.extras.cisAgeS,
  });
  if (lines.length === 0) return null;
  return (
    <section
      role="alert"
      aria-label={t("authority.degraded.title")}
      data-testid="degraded-banner"
      className="border-b border-[var(--us-border)] bg-[var(--us-warning-surface,var(--us-surface-sunken))] px-4 py-2 text-sm"
    >
      <p className="m-0 font-semibold">{t("authority.degraded.title")}</p>
      <ul className="m-0 ps-5">
        {lines.map((l) => (
          <li key={l.slug} data-slug={l.slug}>
            {t(l.key, {
              ...l.vars,
              ...(typeof l.vars["since"] === "string" ? { since: fmtTimeUTC(l.vars["since"], lang, { seconds: true }) } : {}),
              ...(typeof l.vars["age_s"] === "number" ? { age: fmtAge(l.vars["age_s"], lang) } : {}),
            })}
          </li>
        ))}
      </ul>
    </section>
  );
}

/** The age picture-ws measured when it sent the frame, plus the time this console has held it. */
export function serverAgeS(x: HeldExtras | undefined, nowMs: number): number | null {
  if (x === undefined) return null;
  const held = (nowMs - x.receivedAtMs) / 1000;
  return Number.isFinite(held) ? x.ageS + Math.max(0, held) : null;
}

function trackName(tr: TrackView): string {
  return tr.identification?.serial ?? tr.trackId;
}

/** Every held track, newest first, with trust, identification, age and the source's state. */
export function TrackList(props: {
  tracks: readonly TrackView[];
  extras: ReadonlyMap<string, HeldExtras>;
  nowMs: number;
  staleAfterS: number | null;
  selectedId: string | null;
  onSelect(id: string): void;
}) {
  const t = useT();
  const { lang } = useLang();
  if (props.tracks.length === 0) {
    return (
      <p className="m-0 text-sm text-[var(--us-text-muted)]" data-testid="tracks-empty">
        {t("authority.tracks.empty")}
      </p>
    );
  }
  return (
    <ul className="m-0 flex flex-col gap-1 p-0" aria-label={t("authority.tracks.title")} data-testid="track-list">
      {props.tracks.map((tr) => {
        const drawn = identDrawn(tr.identification);
        const x = props.extras.get(tr.trackId);
        const selected = props.selectedId === tr.trackId;
        return (
          <li key={tr.trackId} className="list-none" data-track={tr.trackId} data-trust={tr.trust} data-ident={drawn}>
            <button
              type="button"
              aria-pressed={selected}
              onClick={() => props.onSelect(tr.trackId)}
              className={`flex w-full flex-col items-start gap-0.5 rounded border px-2 py-1 text-start text-xs ${selected ? "border-[var(--us-focus)]" : "border-[var(--us-border)]"}`}
            >
              <span className="font-semibold">{trackName(tr)}</span>
              <span>
                {t(TRUST_KEYS[tr.trust])} · {t(IDENT_STATUS_KEYS[drawn])}
                {tr.identification?.mismatch === true && <> · {t("ident.mismatch_short")}</>}
              </span>
              {isUnverifiedClaim(tr) && (
                <span className="font-semibold" data-testid="unverified">
                  {t(tr.trust === "provider" || tr.identification?.basis === "provider" ? "authority.tracks.unverified_provider" : "authority.tracks.unverified")}
                </span>
              )}
              <span className="flex flex-wrap items-center gap-2">
                <AgeChip ageS={ageS(tr, props.nowMs)} staleAfterS={props.staleAfterS} />
                <span>{t("authority.tracks.server_age", { age: fmtAge(serverAgeS(x, props.nowMs), lang) })}</span>
                {x !== undefined && (
                  <span data-testid="source-state">{t(`authority.tracks.source_state.${x.sourceState}`)}</span>
                )}
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

/** The selected track: every value with its datum, the identification with its caveat. */
export function TrackDetail(props: { track: TrackView; extras: HeldExtras | undefined; nowMs: number; onClose(): void }) {
  const t = useT();
  const { lang } = useLang();
  const tr = props.track;
  const id = tr.identification;
  const hint = id === null ? null : identHintKey(id.status, id.reason, id.basis, id.mismatch);
  const rows: [string, string][] = [
    [t("authority.track.id"), tr.trackId],
    [t("authority.track.trust"), t(TRUST_KEYS[tr.trust])],
    [t("authority.track.source"), `${tr.source} / ${tr.sourceInstance}`],
    [t("authority.track.ident"), t(IDENT_STATUS_KEYS[identDrawn(id)])],
    [t("authority.track.serial"), id?.serial ?? t("common.not_provided")],
    [t("authority.track.operator_reg"), id?.operatorReg == null ? t("common.not_provided") : fmtRegistrationNumber(id.operatorReg)],
    [
      t("authority.track.registered_operator_reg"),
      id?.registeredOperatorReg == null ? t("common.not_provided") : fmtRegistrationNumber(id.registeredOperatorReg),
    ],
    [t("authority.track.altitude"), fmtAltitude(tr.altAmslM, tr.altSource, lang)],
    [t("authority.track.height"), fmtHeight(tr.heightM, tr.heightRef, lang)],
    [t("authority.track.speed"), fmtSpeed(tr.speedMs, lang)],
    [t("authority.track.captured"), fmtTimeUTC(tr.times.capturedAt, lang, { seconds: true })],
    [t("authority.track.age_received"), fmtAge(ageS(tr, props.nowMs), lang)],
    [t("authority.track.age_server"), fmtAge(serverAgeS(props.extras, props.nowMs), lang)],
  ];
  return (
    <section aria-label={t("authority.track.title")} data-testid="track-detail" className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2 text-xs">
      <div className="flex items-center justify-between">
        <h2 className="m-0 text-sm font-semibold">{trackName(tr)}</h2>
        <button type="button" className="underline" onClick={props.onClose}>
          {t("action.close")}
        </button>
      </div>
      {isUnverifiedClaim(tr) && <p className="m-0 font-semibold">{t(tr.trust === "provider" ? "track.provider" : "track.broadcast_caveat")}</p>}
      <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-[var(--us-text-muted)]">{k}</dt>
            <dd className="m-0 break-all">{v}</dd>
          </div>
        ))}
      </dl>
      {hint !== null && (
        <ul className="m-0 ps-4">
          <li>{t(hint.reason)}</li>
          {hint.caveat !== null && <li className="font-semibold">{t(hint.caveat)}</li>}
          {hint.mismatch !== null && <li className="font-semibold">{t(hint.mismatch)}</li>}
        </ul>
      )}
      {id !== null && <p className="m-0 text-[var(--us-text-muted)]">{t(IDENT_REASON_KEYS[id.reason])}</p>}
    </section>
  );
}

/** The active violations: from the snapshot on connect (C-08), then every raise, update and clear. */
export function ViolationsPanel(props: {
  alerts: readonly AlertView[];
  violations: ReadonlyMap<string, AdaptedViolation>;
  tracks: ReadonlyMap<string, TrackView>;
  onSelect(trackId: string): void;
}) {
  const t = useT();
  const { lang } = useLang();
  return (
    <section aria-label={t("authority.violations.title")} data-testid="violations" className="flex flex-col gap-1">
      <h2 className="m-0 text-sm font-semibold">{t("authority.violations.title")}</h2>
      {props.alerts.length === 0 ? (
        <p className="m-0 text-xs text-[var(--us-text-muted)]" data-testid="violations-empty">
          {t("authority.violations.empty")}
        </p>
      ) : (
        <ul className="m-0 flex flex-col gap-1 p-0">
          {props.alerts.map((a) => {
            const v = props.violations.get(a.alertId);
            const trackId = a.aircraft[0] ?? "";
            const track = props.tracks.get(trackId);
            return (
              <li key={a.alertId} className="list-none rounded border border-[var(--us-border)] p-1 text-xs" data-violation={a.alertId} data-state={a.state}>
                <p className="m-0 font-semibold">
                  {t(SEVERITY_KEYS[a.severity])} · {t(`authority.violation.kind.${a.kind}`)}
                  {a.state === "cleared" && (
                    <> · {t("authority.violations.cleared", { reason: t(`authority.violation.clear.${v?.clearReason ?? "unknown"}`) })}</>
                  )}
                </p>
                <p className="m-0">
                  {t("authority.violations.opened", { at: fmtTimeUTC(a.raisedAt, lang, { seconds: true }) })} ·{" "}
                  {t("authority.violations.policy", { version: a.policyVersion })}
                </p>
                {v !== undefined && (v.serial !== null || v.operatorReg !== null) && (
                  <p className="m-0">
                    {t("authority.violations.identity", {
                      serial: v.serial ?? t("common.not_provided"),
                      operator: v.operatorReg === null ? t("common.not_provided") : fmtRegistrationNumber(v.operatorReg),
                    })}
                  </p>
                )}
                {track !== undefined && isUnverifiedClaim(track) && <p className="m-0">{t("alert.broadcast_caveat")}</p>}
                {trackId !== "" && (
                  <button type="button" className="underline" onClick={() => props.onSelect(trackId)}>
                    {t("authority.violations.show_track")}
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
