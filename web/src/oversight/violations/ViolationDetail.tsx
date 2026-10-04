"use client";

// /<locale>/violations/<id> (inspector): one violation as api holds it.
// The evidence excerpt is drawn in api's segments and holes, each hole
// labelled with every cause api names and nothing drawn across it
// (B-13). Every number carries its unit and datum; every height over the
// ground names the terrain dataset and spacing it was taken from, with
// the dataset's attribution (D-05). Broadcast evidence says it can be
// spoofed (06 §2 T1, R-05). The review is api's workflow: a final
// decision (dismissed, escalated) is never offered again, and a 409 is
// shown as final.
import Link from "next/link";
import { useState } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { fmtAltitude, fmtHeading, fmtNum, fmtRegistrationNumber, fmtSpeed, fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { AltSource } from "@rootxkit/uspace-ui/model";
import { Badge, Button, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../../common/Table";
import type { components } from "../../api/types";
import { LoadNotice, ProblemText } from "../../common/Problem";
import { Choice, Facts, PageHeader, Part, TextInput } from "../../common/ui";
import { must, useClient, useLoad } from "../../common/useApi";
import { consolePath } from "../../shell/paths";
import { REVIEW_DECISIONS } from "../enums";
import { ExcerptMap } from "./ExcerptMap";
import { excerptView, type Sample } from "./excerpt";
import { TrustWords } from "./ViolationsList";

type Violation = components["schemas"]["Violation"];
type Hole = components["schemas"]["ViolationExcerptHole"];

/** The terrain a height over the ground was taken from (violation terrain_source, D-05). */
export function TerrainNote({ terrain }: { terrain: Violation["terrain_source"] }) {
  const t = useT();
  const { lang } = useLang();
  const dataset = typeof terrain?.["dataset"] === "string" ? terrain["dataset"] : null;
  const spacing = typeof terrain?.["spacing_m"] === "number" ? terrain["spacing_m"] : null;
  const attribution = typeof terrain?.["attribution"] === "string" ? terrain["attribution"] : null;
  if (dataset === null) {
    return (
      <span className="text-[var(--us-danger)]" data-testid="terrain-note">
        {t("authority.violation_detail.terrain_unrecorded")}
      </span>
    );
  }
  return (
    <span className="text-[var(--us-text-muted)]" data-testid="terrain-note">
      {t("authority.violation_detail.terrain", { dataset, spacing: fmtNum(spacing, 0, "m", lang) })}
      {attribution !== null && <span className="ms-1" data-testid="terrain-attribution">{attribution}</span>}
    </span>
  );
}

/** A height over the ground with the terrain it rests on, always together. */
function AglFigure({ value, terrain, testId }: { value: number; terrain: Violation["terrain_source"]; testId?: string }) {
  const { lang } = useLang();
  return (
    <span className="flex flex-col" data-testid={testId}>
      <span>{fmtAltitude(value, "AGL", lang)}</span>
      <TerrainNote terrain={terrain} />
    </span>
  );
}

/** The judgement's numbers with their datums; every other member as uspace-core named it. */
function DetailFacts({ v }: { v: Violation }) {
  const t = useT();
  const { lang } = useLang();
  const d = v.detail;
  const n = (k: string) => (typeof d[k] === "number" ? (d[k] as number) : null);
  const known = new Set(["height_agl_m", "max_height_agl_m", "alt_hae_m"]);
  const rest = Object.entries(d).filter(([k]) => !known.has(k));
  const height = n("height_agl_m");
  const limit = n("max_height_agl_m");
  const hae = n("alt_hae_m");
  return (
    <div className="flex flex-col gap-2">
      <Facts
        testId="violation-numbers"
        items={[
          ...(height === null ? [] : [{ labelKey: "authority.violation_detail.height_agl", value: <AglFigure value={height} terrain={v.terrain_source} testId="height-agl" /> }]),
          ...(limit === null ? [] : [{ labelKey: "authority.violation_detail.max_height_agl", value: <AglFigure value={limit} terrain={v.terrain_source} /> }]),
          ...(hae === null ? [] : [{ labelKey: "authority.violation_detail.alt_hae", value: fmtAltitude(hae, "WGS84", lang) }]),
        ]}
      />
      {rest.length > 0 && (
        <div className="flex flex-col gap-1">
          <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("authority.violation_detail.detail_as_given")}</p>
          <dl className="m-0 grid grid-cols-[max-content_1fr] gap-x-4 text-xs" data-testid="violation-detail-members">
            {rest.map(([k, val]) => (
              <div key={k} className="contents">
                <dt className="font-mono">{k}</dt>
                <dd className="m-0 font-mono">{JSON.stringify(val)}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}

/** A sample's altitude by its source's datum: pressure is never AMSL (R-08). */
function SampleAltitude({ s }: { s: Sample }) {
  const { lang } = useLang();
  const src = (s.altSource ?? "none") as AltSource;
  if (src === "pressure") return <>{fmtAltitude(s.altPressureM, "pressure", lang)}</>;
  if (s.altAmslM !== null) return <>{fmtAltitude(s.altAmslM, "AMSL", lang)}</>;
  if (s.altWgs84M !== null) return <>{fmtAltitude(s.altWgs84M, "WGS84", lang)}</>;
  return <>{fmtAltitude(null, "none", lang)}</>;
}

function SampleRow({ s }: { s: Sample }) {
  const { lang } = useLang();
  return (
    <TableRow data-sample={s.index}>
      <TableCell>{fmtTimeUTC(s.capturedAt, lang, { seconds: true })}</TableCell>
      <TableCell className="font-mono">{s.lat === null || s.lng === null ? "—" : `${fmtNum(s.lat, 6)}, ${fmtNum(s.lng, 6)}`}</TableCell>
      <TableCell>
        <SampleAltitude s={s} />
      </TableCell>
      <TableCell>{fmtSpeed(s.speedMs, lang)}</TableCell>
      <TableCell>{fmtHeading(s.trackDeg)}</TableCell>
      <TableCell>{s.trust === null ? "—" : <TrustWords trust={s.trust} />}</TableCell>
    </TableRow>
  );
}

function HoleRow({ hole }: { hole: Hole }) {
  const t = useT();
  const { lang } = useLang();
  return (
    <TableRow data-testid="excerpt-hole" className="bg-[var(--us-surface-sunken)]">
      <TableCell colSpan={6}>
        <span className="font-semibold">
          {t("authority.violation_detail.hole", {
            duration: fmtNum(hole.duration_s, 1, "s", lang),
            from: fmtTimeUTC(hole.from, lang, { seconds: true }),
            to: fmtTimeUTC(hole.to, lang, { seconds: true }),
          })}
        </span>
        <ul className="m-0 ps-5" data-testid="hole-causes">
          {hole.causes.map((c) => (
            <li key={c} data-cause={c}>
              {t(`authority.hole.${c.replaceAll(" ", "_")}`)}
            </li>
          ))}
          {hole.recorded.map((r) => (
            <li key={r} className="font-mono text-xs">
              {r}
            </li>
          ))}
        </ul>
      </TableCell>
    </TableRow>
  );
}

function SampleHead() {
  const t = useT();
  return (
    <TableHeader>
      <TableRow>
        <TableHead>{t("authority.excerpt.captured")}</TableHead>
        <TableHead>{t("authority.excerpt.position")}</TableHead>
        <TableHead>{t("authority.excerpt.altitude")}</TableHead>
        <TableHead>{t("authority.excerpt.speed")}</TableHead>
        <TableHead>{t("authority.excerpt.track")}</TableHead>
        <TableHead>{t("authority.excerpt.trust")}</TableHead>
      </TableRow>
    </TableHeader>
  );
}

function Excerpt({ v }: { v: Violation }) {
  const t = useT();
  const { lang } = useLang();
  const view = excerptView(v);
  return (
    <Part titleKey="authority.violation_detail.excerpt" testId="excerpt">
      {v.excerpt_truncated && (
        <p role="status" className="m-0 text-sm" data-testid="excerpt-truncated">
          {t("authority.violation_detail.excerpt_truncated", { count: v.excerpt_samples })}
        </p>
      )}
      {view.mode === "unjoined" ? (
        <p role="status" className="m-0 text-sm" data-testid="excerpt-unjoined">
          {t("authority.violation_detail.excerpt_unjoined", { reason: view.reason })}
        </p>
      ) : (
        <p className="m-0 text-xs text-[var(--us-text-muted)]" data-testid="excerpt-rule">
          {t(view.writerGapsRead ? "authority.violation_detail.excerpt_rule" : "authority.violation_detail.excerpt_rule_gaps_unread", {
            gap: fmtNum(view.maxGapS, 1, "s", lang),
            policy: view.policyVersion ?? "—",
          })}
        </p>
      )}
      <ExcerptMap view={view} />
      <Table data-testid="excerpt-samples">
        <TableCaption>{t("authority.violation_detail.excerpt_caption")}</TableCaption>
        <SampleHead />
        <TableBody>
          {view.mode === "unjoined"
            ? view.samples.map((s) => <SampleRow key={s.index} s={s} />)
            : view.runs.map((r, i) =>
                r.kind === "hole" ? (
                  <HoleRow key={`h${i}`} hole={r.hole} />
                ) : (
                  r.samples.map((s) => <SampleRow key={s.index} s={s} />)
                ),
              )}
        </TableBody>
      </Table>
      {view.mode === "cut" && view.unplaced.length > 0 && (
        <p role="status" className="m-0 text-sm" data-testid="excerpt-unplaced">
          {t("authority.violation_detail.excerpt_unplaced", { count: view.unplaced.length })}
        </p>
      )}
    </Part>
  );
}

function Review({ v, onDone }: { v: Violation; onDone(next: Violation): void }) {
  const t = useT();
  const client = useClient();
  const [decision, setDecision] = useState<string>("reviewed");
  const [note, setNote] = useState("");
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  if (v.status === "dismissed" || v.status === "escalated") {
    return (
      <p className="m-0 text-sm" data-testid="review-final">
        {t("authority.violation_detail.review_final", { status: t(`authority.violation.status.${v.status}`) })}
      </p>
    );
  }
  // Broadcast evidence is never escalated without a note (06 §2 T1); api refuses it too.
  const noteRequired = decision === "escalated" && v.evidence_trust === "broadcast";
  return (
    <form
      className="flex flex-col gap-3"
      data-testid="review-form"
      onSubmit={(e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        client
          .POST("/v1/violations/{violation_id}/review", {
            params: { path: { violation_id: v.violation_id } },
            body: { decision: decision as (typeof REVIEW_DECISIONS)[number], ...(note.trim() === "" ? {} : { note: note.trim() }) },
          })
          .then((r) => onDone(must(r)))
          .catch((err: unknown) => {
            if (err instanceof ApiError) setError(err);
          })
          .finally(() => setBusy(false));
      }}
    >
      <Choice
        name="decision"
        labelKey="authority.violation_detail.decision"
        value={decision}
        onChange={setDecision}
        options={REVIEW_DECISIONS.map((d) => ({ value: d, labelKey: `authority.violation.decision.${d}` }))}
        testId="review-decision"
      />
      <TextInput
        name="note"
        multiline
        labelKey="authority.violation_detail.note"
        hintKey={noteRequired ? "authority.violation_detail.note_required" : "authority.violation_detail.note_hint"}
        value={note}
        onChange={setNote}
        required={noteRequired}
        maxLength={4000}
        testId="review-note"
      />
      {error !== null && <ProblemText error={error} />}
      <div>
        <Button type="submit" disabled={busy} data-testid="review-submit">
          {t("authority.violation_detail.review_submit")}
        </Button>
      </div>
    </form>
  );
}

function IncidentLink({ violationId }: { violationId: string }) {
  const t = useT();
  const { lang } = useLang();
  const { state } = useLoad(`incident-of:${violationId}`, async (c) =>
    must(await c.GET("/v1/incidents", { params: { query: { violation_id: violationId, limit: 1 } } })),
  );
  if (state.kind !== "loaded") return <LoadNotice state={state} />;
  const inc = state.data.incidents[0];
  if (inc === undefined) return <p className="m-0 text-sm">{t("authority.violation_detail.incident_pending")}</p>;
  return (
    <Link className="underline underline-offset-2" href={consolePath(lang, `/incidents/${inc.incident_id}`)} data-testid="incident-link">
      {t("authority.violation_detail.incident_open", { id: inc.incident_id })}
    </Link>
  );
}

export function ViolationDetail({ id }: { id: string }) {
  const t = useT();
  const { lang } = useLang();
  const { state } = useLoad(`violation:${id}`, async (c) => must(await c.GET("/v1/violations/{violation_id}", { params: { path: { violation_id: id } } })));
  const [reviewed, setReviewed] = useState<Violation | null>(null);
  if (state.kind !== "loaded") {
    return (
      <div className="p-4">
        <LoadNotice state={state} />
      </div>
    );
  }
  // The review answer is the violation as reviewed (without the cut, which GET alone carries).
  const v: Violation = reviewed === null ? state.data : { ...reviewed, excerpt_segmenting: state.data.excerpt_segmenting };
  return (
    <div className="flex flex-col gap-4 p-4" data-testid="violation-detail" data-status={v.status}>
      <PageHeader titleKey="authority.violation_detail.title" vars={{ kind: t(`authority.violation.kind.${v.kind}`) }}>
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline">{t(`severity.${v.severity}`)}</Badge>
          <Badge variant="outline" data-testid="violation-status">
            {t(`authority.violation.status.${v.status}`)}
          </Badge>
        </div>
      </PageHeader>
      {v.evidence_trust === "broadcast" && (
        <p role="note" className="m-0 rounded-md border border-[var(--us-trust-broadcast)] p-2 text-sm" data-testid="broadcast-warning">
          {t("authority.violation_detail.broadcast_warning")}
        </p>
      )}
      <Part titleKey="authority.violation_detail.facts">
        <Facts
          items={[
            { labelKey: "authority.violation_detail.id", value: <span className="font-mono">{v.violation_id}</span> },
            { labelKey: "authority.violation_detail.track", value: <span className="font-mono">{v.track_id}</span> },
            { labelKey: "authority.violation_detail.serial", value: v.serial ?? "—" },
            { labelKey: "authority.violation_detail.operator_reg", value: fmtRegistrationNumber(v.operator_reg ?? null) },
            { labelKey: "authority.violation_detail.evidence_trust", value: <TrustWords trust={v.evidence_trust} /> },
            {
              labelKey: "authority.violation_detail.zone",
              value: v.zone_id === null || v.zone_id === undefined ? "—" : t("authority.violation_detail.zone_value", { id: v.zone_id, version: v.zone_version ?? "—", type: v.zone_type ?? "—" }),
            },
            { labelKey: "authority.violation_detail.in_uspace", value: t(v.in_uspace ? "authority.common.yes" : "authority.common.no") },
            { labelKey: "authority.violation_detail.opened", value: fmtTimeUTC(v.opened_at, lang, { seconds: true }) },
            {
              labelKey: "authority.violation_detail.closed",
              value:
                v.closed_at === null || v.closed_at === undefined
                  ? t("authority.violations_page.open")
                  : t("authority.violations_page.closed_value", {
                      at: fmtTimeUTC(v.closed_at, lang, { seconds: true }),
                      reason: t(`authority.violation.clear.${v.clear_reason ?? "unknown"}`),
                    }),
            },
            {
              labelKey: "authority.violation_detail.policy",
              value: v.policy_version === 0 ? t("authority.violation_detail.policy_defaults") : String(v.policy_version),
            },
            {
              labelKey: "authority.violation_detail.peak",
              value:
                v.peak === undefined ? "—" : v.peak.name === "height_agl_m" ? <AglFigure value={v.peak.value} terrain={v.terrain_source} testId="peak-agl" /> : `${v.peak.name} ${v.peak.value}`,
            },
          ]}
        />
        <DetailFacts v={v} />
      </Part>
      <Excerpt v={v} />
      <Part titleKey="authority.violation_detail.review" testId="review">
        {v.reviewed_at !== null && v.reviewed_at !== undefined && (
          <p className="m-0 text-sm" data-testid="review-last">
            {t("authority.violation_detail.reviewed_by", { who: v.reviewed_by ?? "—", at: fmtTimeUTC(v.reviewed_at, lang), note: v.review_note ?? "" })}
          </p>
        )}
        <Review v={v} onDone={setReviewed} />
        {(v.status === "escalated" || v.incident_requested) && <IncidentLink violationId={v.violation_id} />}
      </Part>
    </div>
  );
}
