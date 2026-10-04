"use client";

// The occurrence officer realm (WP-23; incident_officer only, 376/2014
// Art. 15-16): the intake queue with the 72 h flag, one report with its
// reporter block rendered only when api returns it (a purpose-logged
// read, refused to every other role), the risk classification and the
// analysis, and the de-identified export, which says that a free-text
// narrative is exported as the reporter wrote it. The reports are never
// joined to violations or incidents: nothing here links to them.
import Link from "next/link";
import { useState } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { fmtNum, fmtRegistrationNumber, fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Badge, Button, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../../common/Table";
import type { components } from "../../api/types";
import { LoadNotice, ProblemText } from "../../common/Problem";
import { Choice, Facts, PageHeader, Part, TextInput, saveBlob } from "../../common/ui";
import { must, useClient, useLoad } from "../../common/useApi";
import { consolePath } from "../../shell/paths";
import { ANALYSIS_STATES, OCCURRENCE_CATEGORIES, OCCURRENCE_CHANNELS, OCCURRENCE_STATES } from "../enums";

type S = components["schemas"];
type Occurrence = S["Occurrence"];

const PAGE_LIMIT = 50;

/** The 376 Art. 4(7)-(8) flag as api set it at intake. */
function Deadline({ within }: { within: boolean }) {
  const t = useT();
  return within ? (
    <span data-testid="within-72h" data-within="true">
      {t("authority.occurrences.within_72h")}
    </span>
  ) : (
    <Badge variant="destructive" data-testid="within-72h" data-within="false">
      {t("authority.occurrences.late")}
    </Badge>
  );
}

export function OccurrenceQueue() {
  const t = useT();
  const { lang } = useLang();
  const [state, setState] = useState("");
  const [category, setCategory] = useState("");
  const [channel, setChannel] = useState("");
  const [cursors, setCursors] = useState<string[]>([]);
  const cursor = cursors.at(-1);
  const { state: load } = useLoad(JSON.stringify({ state, category, channel, cursor }), async (c) =>
    must(
      await c.GET("/v1/occurrences", {
        params: {
          query: {
            limit: PAGE_LIMIT,
            ...(state === "" ? {} : { state: state as S["OccurrenceState"] }),
            ...(category === "" ? {} : { category: category as S["OccurrenceCategory"] }),
            ...(channel === "" ? {} : { channel: channel as S["OccurrenceChannel"] }),
            ...(cursor === undefined ? {} : { cursor }),
          },
        },
      }),
    ),
  );
  const rows = load.kind === "loaded" ? load.data.occurrences : [];
  const next = load.kind === "loaded" ? load.data.next_cursor : undefined;
  const reset = () => setCursors([]);
  return (
    <div className="flex flex-col gap-4 p-4">
      <PageHeader titleKey="authority.occurrences.title" introKey="authority.occurrences.intro">
        <Link className="underline underline-offset-2 text-sm" href={consolePath(lang, "/occurrences/export")} data-testid="occurrences-export-link">
          {t("authority.occurrences.export_link")}
        </Link>
      </PageHeader>
      <div className="flex flex-wrap items-end gap-3">
        <Choice name="state" labelKey="authority.occurrences.state" anyKey="authority.common.any" value={state} onChange={(v) => { reset(); setState(v); }} options={OCCURRENCE_STATES.map((s) => ({ value: s, labelKey: `authority.occurrence.state.${s}` }))} />
        <Choice name="category" labelKey="authority.occurrences.category" anyKey="authority.common.any" value={category} onChange={(v) => { reset(); setCategory(v); }} options={OCCURRENCE_CATEGORIES.map((s) => ({ value: s, labelKey: `authority.occurrence.category.${s}` }))} />
        <Choice name="channel" labelKey="authority.occurrences.channel" anyKey="authority.common.any" value={channel} onChange={(v) => { reset(); setChannel(v); }} options={OCCURRENCE_CHANNELS.map((s) => ({ value: s, labelKey: `authority.occurrence.channel.${s}` }))} />
      </div>
      <LoadNotice state={load} />
      {load.kind === "loaded" && (
        <Table data-testid="occurrences-table">
          <TableCaption>{t("authority.occurrences.caption")}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>{t("authority.occurrences.received")}</TableHead>
              <TableHead>{t("authority.occurrences.deadline")}</TableHead>
              <TableHead>{t("authority.occurrences.category")}</TableHead>
              <TableHead>{t("authority.occurrences.channel")}</TableHead>
              <TableHead>{t("authority.occurrences.origin")}</TableHead>
              <TableHead>{t("authority.occurrences.state")}</TableHead>
              <TableHead>{t("authority.occurrences.risk")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={7}>{t("authority.occurrences.empty")}</TableCell>
              </TableRow>
            )}
            {rows.map((o) => (
              <TableRow key={o.occurrence_id} data-occurrence-row={o.occurrence_id}>
                <TableCell>
                  <Link className="underline underline-offset-2" href={consolePath(lang, `/occurrences/${o.occurrence_id}`)}>
                    {fmtTimeUTC(o.received_at, lang)}
                  </Link>
                </TableCell>
                <TableCell>
                  <Deadline within={o.within_72h} />
                </TableCell>
                <TableCell>{t(`authority.occurrence.category.${o.category}`)}</TableCell>
                <TableCell>{t(`authority.occurrence.channel.${o.channel}`)}</TableCell>
                <TableCell>{t(`authority.occurrence.origin.${o.origin}`)}</TableCell>
                <TableCell>{t(`authority.occurrence.state.${o.state}`)}</TableCell>
                <TableCell>{o.risk_classification ?? "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <div className="flex gap-2">
        <Button type="button" variant="outline" disabled={cursors.length === 0} onClick={() => setCursors(cursors.slice(0, -1))}>
          {t("authority.common.previous")}
        </Button>
        <Button type="button" variant="outline" disabled={next === undefined} onClick={() => next !== undefined && setCursors([...cursors, next])}>
          {t("authority.common.next")}
        </Button>
      </div>
    </div>
  );
}

/** The reporter: asked for with a purpose, rendered only from api's answer, never kept. */
function Reporter({ o }: { o: Occurrence }) {
  const t = useT();
  const client = useClient();
  const [purpose, setPurpose] = useState("");
  const [reporter, setReporter] = useState<S["OccurrenceReporter"] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  return (
    <Part titleKey="authority.occurrence_detail.reporter" testId="reporter">
      <p className="m-0 text-sm">{t(o.has_reporter_person ? "authority.occurrence_detail.reporter_held" : "authority.occurrence_detail.reporter_none")}</p>
      {reporter === null ? (
        <form
          className="flex flex-wrap items-end gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (purpose.trim() === "") return;
            setError(null);
            client
              .GET("/v1/occurrences/{occurrence_id}/reporter", { params: { path: { occurrence_id: o.occurrence_id }, query: { purpose: purpose.trim() } } })
              .then((r) => setReporter(must(r)))
              .catch((err: unknown) => {
                if (err instanceof ApiError) setError(err);
              });
          }}
        >
          <TextInput name="purpose" required maxLength={200} labelKey="authority.occurrence_detail.reporter_purpose" hintKey="authority.occurrence_detail.reporter_purpose_hint" value={purpose} onChange={setPurpose} testId="reporter-purpose" />
          <Button type="submit" variant="outline" data-testid="reporter-open">
            {t("authority.occurrence_detail.reporter_open")}
          </Button>
        </form>
      ) : (
        <div data-testid="reporter-block">
          <Facts
            items={[
              { labelKey: "authority.occurrence_detail.reporter_org", value: reporter.reporter_org },
              { labelKey: "authority.occurrence_detail.report_ref", value: reporter.report_ref },
              { labelKey: "authority.occurrence_detail.person_ref", value: reporter.person_ref ?? t("authority.occurrence_detail.person_ref_none") },
            ]}
          />
          <Button type="button" variant="outline" size="sm" className="mt-2" onClick={() => setReporter(null)}>
            {t("authority.occurrence_detail.reporter_close")}
          </Button>
        </div>
      )}
      {error !== null && <ProblemText error={error} />}
    </Part>
  );
}

function Handling({ o, onDone }: { o: Occurrence; onDone(o: Occurrence): void }) {
  const t = useT();
  const client = useClient();
  const [risk, setRisk] = useState(o.risk_classification ?? "");
  const [analysis, setAnalysis] = useState(o.analysis);
  const [followUp, setFollowUp] = useState(o.follow_up);
  const [next, setNext] = useState("");
  const [error, setError] = useState<ApiError | null>(null);
  const fail = (err: unknown) => {
    if (err instanceof ApiError) setError(err);
  };
  if (o.state === "closed") return <p className="m-0 text-sm">{t("authority.occurrence_detail.closed")}</p>;
  return (
    <div className="flex flex-col gap-4">
      <form
        className="flex flex-wrap items-end gap-3"
        data-testid="classify-form"
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          client
            .POST("/v1/occurrences/{occurrence_id}/classify", { params: { path: { occurrence_id: o.occurrence_id } }, body: { risk_classification: risk.trim() } })
            .then((r) => onDone(must(r)))
            .catch(fail);
        }}
      >
        <TextInput name="risk_classification" required maxLength={64} labelKey="authority.occurrence_detail.risk" hintKey="authority.occurrence_detail.risk_hint" value={risk} onChange={setRisk} testId="risk-input" />
        <Button type="submit" data-testid="classify-submit">
          {t("authority.occurrence_detail.classify")}
        </Button>
      </form>
      <form
        className="flex flex-col gap-3"
        data-testid="analysis-form"
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          client
            .PATCH("/v1/occurrences/{occurrence_id}/analysis", {
              params: { path: { occurrence_id: o.occurrence_id } },
              body: { analysis, follow_up: followUp, ...(next === "" ? {} : { state: next as NonNullable<S["OccurrenceAnalysisPatch"]["state"]> }) },
            })
            .then((r) => onDone(must(r)))
            .catch(fail);
        }}
      >
        <TextInput name="analysis" multiline maxLength={20000} labelKey="authority.occurrence_detail.analysis" value={analysis} onChange={setAnalysis} testId="analysis-input" />
        <TextInput name="follow_up" multiline maxLength={20000} labelKey="authority.occurrence_detail.follow_up" value={followUp} onChange={setFollowUp} />
        <Choice name="state" labelKey="authority.occurrence_detail.next_state" anyKey="authority.occurrence_detail.state_unchanged" value={next} onChange={setNext} options={ANALYSIS_STATES.map((s) => ({ value: s, labelKey: `authority.occurrence.state.${s}` }))} />
        <div>
          <Button type="submit" data-testid="analysis-submit">
            {t("authority.common.save")}
          </Button>
        </div>
      </form>
      {error !== null && <ProblemText error={error} />}
    </div>
  );
}

export function OccurrenceDetail({ id }: { id: string }) {
  const t = useT();
  const { lang } = useLang();
  const { state } = useLoad(`occurrence:${id}`, async (c) => must(await c.GET("/v1/occurrences/{occurrence_id}", { params: { path: { occurrence_id: id } } })));
  const [changed, setChanged] = useState<Occurrence | null>(null);
  if (state.kind !== "loaded") {
    return (
      <div className="p-4">
        <LoadNotice state={state} />
      </div>
    );
  }
  const o = changed ?? state.data;
  return (
    <div className="flex flex-col gap-4 p-4" data-testid="occurrence-detail" data-state={o.state}>
      <PageHeader titleKey="authority.occurrence_detail.title" vars={{ category: t(`authority.occurrence.category.${o.category}`) }}>
        <div className="flex flex-wrap gap-2">
          <Deadline within={o.within_72h} />
          <Badge variant="outline">{t(`authority.occurrence.state.${o.state}`)}</Badge>
        </div>
      </PageHeader>
      <Part titleKey="authority.occurrence_detail.report">
        <Facts
          items={[
            { labelKey: "authority.occurrence_detail.id", value: <span className="font-mono">{o.occurrence_id}</span> },
            { labelKey: "authority.occurrences.channel", value: t(`authority.occurrence.channel.${o.channel}`) },
            { labelKey: "authority.occurrences.origin", value: t(`authority.occurrence.origin.${o.origin}`) },
            { labelKey: "authority.occurrence_detail.occurred", value: fmtTimeUTC(o.occurred_at, lang, { seconds: true }) },
            { labelKey: "authority.occurrence_detail.became_aware", value: fmtTimeUTC(o.became_aware_at, lang, { seconds: true }) },
            { labelKey: "authority.occurrences.received", value: fmtTimeUTC(o.received_at, lang, { seconds: true }) },
            { labelKey: "authority.occurrence_detail.deadline_s", value: t("authority.occurrence_detail.deadline_value", { hours: fmtNum(o.report_deadline_s / 3600, 0) }) },
            { labelKey: "authority.occurrences.risk", value: o.risk_classification ?? "—" },
            {
              labelKey: "authority.occurrence_detail.separation",
              value:
                o.min_separation === null || o.min_separation === undefined
                  ? "—"
                  : t("authority.occurrence_detail.separation_value", {
                      h: fmtNum(o.min_separation.h_m ?? null, 0, "m", lang),
                      v: fmtNum(o.min_separation.v_m ?? null, 0, "m", lang),
                      at: fmtTimeUTC(o.min_separation.at ?? null, lang),
                    }),
            },
          ]}
        />
        {o.aircraft.length > 0 && (
          <ul className="m-0 ps-5 text-sm" data-testid="occurrence-aircraft">
            {o.aircraft.map((a, i) => (
              <li key={i}>
                {t("authority.occurrence_detail.aircraft_value", {
                  serial: a.serial ?? "—",
                  operator: fmtRegistrationNumber(a.operator_reg ?? null),
                  flight: a.flight_id ?? "—",
                  authorisation: a.authorisation_number ?? "—",
                })}
              </li>
            ))}
          </ul>
        )}
        {o.manned.length > 0 && (
          <ul className="m-0 ps-5 text-sm">
            {o.manned.map((m, i) => (
              <li key={i}>{t("authority.occurrence_detail.manned_value", { icao24: m.icao24 ?? "—", callsign: m.callsign ?? "—" })}</li>
            ))}
          </ul>
        )}
        <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("authority.occurrence_detail.narrative_as_written")}</p>
        <p className="m-0 whitespace-pre-wrap text-sm" data-testid="occurrence-narrative">
          {o.narrative}
        </p>
      </Part>
      <Reporter o={o} />
      <Part titleKey="authority.occurrence_detail.handling">
        <Handling key={o.updated_at} o={o} onDone={setChanged} />
      </Part>
    </div>
  );
}

export function OccurrenceExport() {
  const t = useT();
  const { lang } = useLang();
  const client = useClient();
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [result, setResult] = useState<S["OccurrenceExport"] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="flex flex-col gap-4 p-4">
      <PageHeader titleKey="authority.occurrence_export.title" introKey="authority.occurrence_export.intro" />
      <p role="note" className="m-0 rounded-md border border-[var(--us-severity-warning)] p-2 text-sm" data-testid="narrative-warning">
        {t("authority.occurrence_export.narrative_warning")}
      </p>
      <form
        className="flex flex-wrap items-end gap-3"
        data-testid="occurrence-export-form"
        onSubmit={(e) => {
          e.preventDefault();
          const f = inputToUtc(from);
          const tt = inputToUtc(to);
          if (f === null || tt === null) return;
          setBusy(true);
          setError(null);
          setResult(null);
          client
            .POST("/v1/occurrences/export", { body: { from: f, to: tt } })
            .then((r) => setResult(must(r)))
            .catch((err: unknown) => {
              if (err instanceof ApiError) setError(err);
            })
            .finally(() => setBusy(false));
        }}
      >
        <TextInput name="from" type="datetime-local" required labelKey="authority.occurrence_export.from" value={from} onChange={setFrom} testId="export-from" />
        <TextInput name="to" type="datetime-local" required labelKey="authority.occurrence_export.to" value={to} onChange={setTo} testId="export-to" />
        <Button type="submit" disabled={busy} data-testid="export-submit">
          {t("authority.occurrence_export.build")}
        </Button>
      </form>
      {error !== null && <ProblemText error={error} />}
      {result !== null && (
        <Part titleKey="authority.occurrence_export.result" testId="export-result">
          <Facts
            items={[
              { labelKey: "authority.occurrence_export.format", value: result.format },
              { labelKey: "authority.occurrence_export.records", value: String(result.record_count) },
              { labelKey: "authority.occurrence_export.hash", value: <span className="font-mono text-xs break-all">{result.content_hash}</span> },
              { labelKey: "authority.occurrence_export.created", value: fmtTimeUTC(result.created_at, lang, { seconds: true }) },
            ]}
          />
          <div>
            <Button type="button" variant="outline" onClick={() => saveBlob(new Blob([result.content], { type: "application/json" }), `${result.export_id}.json`)} data-testid="export-save">
              {t("authority.occurrence_export.save")}
            </Button>
          </div>
        </Part>
      )}
    </div>
  );
}
