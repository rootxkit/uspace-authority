"use client";

// /<locale>/audit (admin, auditor): the audit log searched (every read
// of it is itself an audit_events_viewed row, with the purpose given
// here), the monthly hash-chain verification as api ran it (a month
// with no rows says so, never "intact" without numbers), and the data
// protection officer's monthly report of police queries and personal
// data reads (itself a dpo_report_viewed row).
import { useState } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Badge, Button, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../../common/Table";
import type { components } from "../../api/types";
import { LoadNotice, ProblemText } from "../../common/Problem";
import { Facts, PageHeader, Part, TextInput } from "../../common/ui";
import { must, useClient, useLoad } from "../../common/useApi";

type S = components["schemas"];

const EVENTS_LIMIT = 100;
const MONTH = /^[0-9]{4}-(0[1-9]|1[0-2])$/;

interface EventFilters {
  entity_type: string;
  entity_id: string;
  actor_id: string;
  event_type: string;
  from: string;
  to: string;
  purpose: string;
}

const EMPTY: EventFilters = { entity_type: "", entity_id: "", actor_id: "", event_type: "", from: "", to: "", purpose: "" };

function EventSearch() {
  const t = useT();
  const { lang } = useLang();
  const [draft, setDraft] = useState<EventFilters>(EMPTY);
  const [applied, setApplied] = useState<EventFilters | null>(null);
  const [before, setBefore] = useState<number[]>([]);
  const beforeId = before.at(-1);
  const { state } = useLoad(applied === null ? null : JSON.stringify({ applied, beforeId }), async (c) => {
    const f = applied ?? EMPTY;
    const from = inputToUtc(f.from);
    const to = inputToUtc(f.to);
    const text = (k: "entity_type" | "entity_id" | "actor_id" | "event_type" | "purpose") => (f[k].trim() === "" ? {} : { [k]: f[k].trim() });
    return must(
      await c.GET("/v1/audit/events", {
        params: {
          query: {
            limit: EVENTS_LIMIT,
            ...text("entity_type"),
            ...text("entity_id"),
            ...text("actor_id"),
            ...text("event_type"),
            ...text("purpose"),
            ...(from === null ? {} : { from }),
            ...(to === null ? {} : { to }),
            ...(beforeId === undefined ? {} : { before_id: beforeId }),
          },
        },
      }),
    );
  });
  const set = (k: keyof EventFilters) => (v: string) => setDraft({ ...draft, [k]: v });
  const next = state.kind === "loaded" ? state.data.next_before_id : undefined;
  return (
    <Part titleKey="authority.audit.events" testId="audit-events">
      <form
        className="grid gap-3 md:grid-cols-4"
        onSubmit={(e) => {
          e.preventDefault();
          setBefore([]);
          setApplied(draft);
        }}
      >
        <TextInput name="entity_type" labelKey="authority.audit.entity_type" value={draft.entity_type} onChange={set("entity_type")} />
        <TextInput name="entity_id" labelKey="authority.audit.entity_id" value={draft.entity_id} onChange={set("entity_id")} />
        <TextInput name="actor_id" labelKey="authority.audit.actor_id" value={draft.actor_id} onChange={set("actor_id")} />
        <TextInput name="event_type" labelKey="authority.audit.event_type" value={draft.event_type} onChange={set("event_type")} />
        <TextInput name="from" type="datetime-local" labelKey="authority.audit.from" value={draft.from} onChange={set("from")} />
        <TextInput name="to" type="datetime-local" labelKey="authority.audit.to" value={draft.to} onChange={set("to")} />
        <TextInput name="purpose" labelKey="authority.audit.purpose" hintKey="authority.audit.purpose_hint" value={draft.purpose} onChange={set("purpose")} />
        <div className="self-end">
          <Button type="submit" data-testid="audit-search">
            {t("authority.audit.search")}
          </Button>
        </div>
      </form>
      <LoadNotice state={state} />
      {state.kind === "loaded" && (
        <Table data-testid="audit-table">
          <TableCaption>{t("authority.audit.caption")}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>{t("authority.audit.id")}</TableHead>
              <TableHead>{t("authority.audit.ts")}</TableHead>
              <TableHead>{t("authority.audit.actor")}</TableHead>
              <TableHead>{t("authority.audit.event_type")}</TableHead>
              <TableHead>{t("authority.audit.entity")}</TableHead>
              <TableHead>{t("authority.audit.purpose")}</TableHead>
              <TableHead>{t("authority.audit.hash")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {state.data.events.length === 0 && (
              <TableRow>
                <TableCell colSpan={7}>{t("authority.audit.empty")}</TableCell>
              </TableRow>
            )}
            {state.data.events.map((ev) => (
              <TableRow key={ev.id} data-event={ev.id}>
                <TableCell>{ev.id}</TableCell>
                <TableCell>{fmtTimeUTC(ev.ts, lang, { seconds: true })}</TableCell>
                <TableCell>{t("authority.audit.actor_value", { type: ev.actor_type, id: ev.actor_id, realm: ev.realm ?? "—" })}</TableCell>
                <TableCell className="font-mono text-xs">{ev.event_type}</TableCell>
                <TableCell className="font-mono text-xs">{`${ev.entity_type}${ev.entity_id === undefined ? "" : `/${ev.entity_id}`}`}</TableCell>
                <TableCell>{ev.purpose ?? "—"}</TableCell>
                <TableCell className="font-mono text-xs" title={ev.hash}>
                  {ev.hash.slice(0, 12)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <div className="flex gap-2">
        <Button type="button" variant="outline" disabled={before.length === 0} onClick={() => setBefore(before.slice(0, -1))}>
          {t("authority.common.previous")}
        </Button>
        <Button type="button" variant="outline" disabled={next === undefined} onClick={() => next !== undefined && setBefore([...before, next])}>
          {t("authority.common.next")}
        </Button>
      </div>
    </Part>
  );
}

function ChainVerification() {
  const t = useT();
  const { lang } = useLang();
  const client = useClient();
  const [month, setMonth] = useState("");
  const [result, setResult] = useState<S["AuditVerification"] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  return (
    <Part titleKey="authority.audit.chain" testId="audit-chain">
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!MONTH.test(month)) return;
          setError(null);
          setResult(null);
          client
            .GET("/v1/audit/verify", { params: { query: { month } } })
            .then((r) => setResult(must(r)))
            .catch((err: unknown) => {
              if (err instanceof ApiError) setError(err);
            });
        }}
      >
        <TextInput name="month" type="month" required labelKey="authority.audit.month" hintKey="authority.audit.month_hint" value={month} onChange={setMonth} testId="chain-month" />
        <Button type="submit" data-testid="chain-verify">
          {t("authority.audit.verify")}
        </Button>
      </form>
      {error !== null && <ProblemText error={error} />}
      {result !== null && (
        <div className="flex flex-col gap-2" data-testid="chain-result" data-intact={String(result.intact)} data-rows={result.rows}>
          <p className="m-0 font-semibold">
            {result.rows === 0
              ? t("authority.audit.chain_no_rows", { month: result.month })
              : t(result.intact ? "authority.audit.chain_intact" : "authority.audit.chain_broken", { month: result.month, rows: result.rows })}
          </p>
          <Facts
            items={[
              { labelKey: "authority.audit.first_last", value: t("authority.audit.first_last_value", { first: result.first_id ?? "—", last: result.last_id ?? "—" }) },
              { labelKey: "authority.audit.last_hash", value: <span className="font-mono text-xs break-all">{result.last_hash ?? "—"}</span> },
              { labelKey: "authority.audit.anchored_to", value: result.anchored_to === undefined || result.anchored_to === "" ? "—" : result.anchored_to },
              ...(result.broken === undefined
                ? []
                : [
                    {
                      labelKey: "authority.audit.broken",
                      value: t("authority.audit.broken_value", { id: result.broken.id, at: fmtTimeUTC(result.broken.ts, lang, { seconds: true }), reason: result.broken.reason }),
                      testId: "chain-broken",
                    },
                  ]),
              { labelKey: "authority.audit.verified_at", value: fmtTimeUTC(result.verified_at, lang, { seconds: true }) },
            ]}
          />
        </div>
      )}
    </Part>
  );
}

function DpoReport() {
  const t = useT();
  const { lang } = useLang();
  const client = useClient();
  const [month, setMonth] = useState("");
  const [report, setReport] = useState<S["DPOReport"] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  return (
    <Part titleKey="authority.dpo.title" testId="dpo-report">
      <p className="m-0 text-sm text-[var(--us-text-muted)]">{t("authority.dpo.intro")}</p>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!MONTH.test(month)) return;
          setError(null);
          setReport(null);
          client
            .GET("/v1/audit/dpo-report", { params: { query: { month } } })
            .then((r) => setReport(must(r)))
            .catch((err: unknown) => {
              if (err instanceof ApiError) setError(err);
            });
        }}
      >
        <TextInput name="month" type="month" required labelKey="authority.audit.month" hintKey="authority.audit.month_hint" value={month} onChange={setMonth} testId="dpo-month" />
        <Button type="submit" data-testid="dpo-read">
          {t("authority.dpo.read")}
        </Button>
      </form>
      {error !== null && <ProblemText error={error} />}
      {report !== null && (
        <div className="flex flex-col gap-3">
          <p className="m-0 text-sm" data-testid="dpo-totals">
            {t("authority.dpo.totals", { queries: report.totals.police_queries, pii: report.totals.police_queries_with_pii, views: report.totals.pii_views })}
          </p>
          {report.truncated && (
            <p role="status" className="m-0 text-sm" data-testid="dpo-truncated">
              {t("authority.dpo.truncated")}
            </p>
          )}
          <Table data-testid="dpo-queries">
            <TableCaption>{t("authority.dpo.queries")}</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead>{t("authority.dpo.at")}</TableHead>
                <TableHead>{t("authority.dpo.who")}</TableHead>
                <TableHead>{t("authority.dpo.kind")}</TableHead>
                <TableHead>{t("authority.dpo.purpose")}</TableHead>
                <TableHead>{t("authority.dpo.case_ref")}</TableHead>
                <TableHead>{t("authority.dpo.results")}</TableHead>
                <TableHead>{t("authority.dpo.pii")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {report.police_queries.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7}>{t("authority.dpo.no_queries")}</TableCell>
                </TableRow>
              )}
              {report.police_queries.map((q) => (
                <TableRow key={q.id}>
                  <TableCell>{fmtTimeUTC(q.at, lang, { seconds: true })}</TableCell>
                  <TableCell>{t("authority.dpo.who_value", { user: q.user_id, agency: q.agency, ip: q.remote_ip })}</TableCell>
                  <TableCell>{q.kind}</TableCell>
                  <TableCell>{q.purpose}</TableCell>
                  <TableCell>{q.case_ref}</TableCell>
                  <TableCell>{q.result_count}</TableCell>
                  <TableCell>{q.pii ? <Badge variant="destructive">{t("authority.common.yes")}</Badge> : t("authority.common.no")}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Table data-testid="dpo-views">
            <TableCaption>{t("authority.dpo.views")}</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead>{t("authority.dpo.at")}</TableHead>
                <TableHead>{t("authority.dpo.event")}</TableHead>
                <TableHead>{t("authority.dpo.who")}</TableHead>
                <TableHead>{t("authority.dpo.purpose")}</TableHead>
                <TableHead>{t("authority.dpo.entity")}</TableHead>
                <TableHead>{t("authority.dpo.case_ref")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {report.pii_views.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6}>{t("authority.dpo.no_views")}</TableCell>
                </TableRow>
              )}
              {report.pii_views.map((v) => (
                <TableRow key={v.event_id}>
                  <TableCell>{fmtTimeUTC(v.ts, lang, { seconds: true })}</TableCell>
                  <TableCell className="font-mono text-xs">{v.event_type}</TableCell>
                  <TableCell>{t("authority.audit.actor_value", { type: v.actor_type, id: v.actor_id, realm: v.realm ?? "—" })}</TableCell>
                  <TableCell>{v.purpose ?? "—"}</TableCell>
                  <TableCell className="font-mono text-xs">{`${v.entity_type}/${v.entity_id ?? ""}`}</TableCell>
                  <TableCell>{v.case_ref ?? "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </Part>
  );
}

export function Audit() {
  return (
    <div className="flex flex-col gap-4 p-4">
      <PageHeader titleKey="authority.audit.title" introKey="authority.audit.intro" />
      <EventSearch />
      <ChainVerification />
      <DpoReport />
    </div>
  );
}
