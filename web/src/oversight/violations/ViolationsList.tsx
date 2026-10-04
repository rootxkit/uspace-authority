"use client";

// /<locale>/violations (inspector): GET /v1/violations with its filters,
// newest first, page by page with the cursor api returns. Every row says
// how the evidence reached the system; broadcast evidence says "as
// broadcast and unverified" (R-05). An empty page is api's answer for
// these filters, said as such (E-02).
import Link from "next/link";
import { useState } from "react";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { fmtAltitude, fmtRegistrationNumber, fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Badge, Button, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../../common/Table";
import type { components } from "../../api/types";
import { LoadNotice } from "../../common/Problem";
import { Choice, PageHeader, TextInput } from "../../common/ui";
import { must, useLoad } from "../../common/useApi";
import { consolePath } from "../../shell/paths";
import { VIOLATION_KINDS, VIOLATION_STATUSES } from "../enums";

type Summary = components["schemas"]["ViolationSummary"];

/** api's page size bound (listViolations limit maximum); a display choice within it. */
const PAGE_LIMIT = 50;

interface Filters {
  status: string;
  kind: string;
  from: string;
  to: string;
}

const NO_FILTERS: Filters = { status: "", kind: "", from: "", to: "" };

export function Peak({ v }: { v: Pick<Summary, "peak"> }) {
  const { lang } = useLang();
  if (v.peak === undefined) return null;
  // height_agl_m is a height over the DEM ground (D-05); any other number is shown as named.
  if (v.peak.name === "height_agl_m") return <>{fmtAltitude(v.peak.value, "AGL", lang)}</>;
  return <>{`${v.peak.name} ${v.peak.value}`}</>;
}

export function TrustWords({ trust }: { trust: string }) {
  const t = useT();
  return (
    <span data-testid="evidence-trust" data-trust={trust}>
      {t(`trust.${trust}`)}
      {trust === "broadcast" && <span className="ms-1 text-[var(--us-text-muted)]" data-testid="unverified">{t("authority.tracks.unverified")}</span>}
      {trust === "provider" && <span className="ms-1 text-[var(--us-text-muted)]" data-testid="unverified">{t("authority.tracks.unverified_provider")}</span>}
    </span>
  );
}

export function ViolationsList() {
  const t = useT();
  const { lang } = useLang();
  const [draft, setDraft] = useState<Filters>(NO_FILTERS);
  const [applied, setApplied] = useState<Filters>(NO_FILTERS);
  // The cursors of the pages before this one, for "previous".
  const [cursors, setCursors] = useState<string[]>([]);
  const cursor = cursors.at(-1);
  const key = JSON.stringify({ applied, cursor });
  const { state } = useLoad(key, async (c) => {
    const from = inputToUtc(applied.from);
    const to = inputToUtc(applied.to);
    return must(
      await c.GET("/v1/violations", {
        params: {
          query: {
            limit: PAGE_LIMIT,
            ...(applied.status === "" ? {} : { status: applied.status as Summary["status"] }),
            ...(applied.kind === "" ? {} : { kind: applied.kind as Summary["kind"] }),
            ...(from === null ? {} : { from }),
            ...(to === null ? {} : { to }),
            ...(cursor === undefined ? {} : { cursor }),
          },
        },
      }),
    );
  });
  const rows = state.kind === "loaded" ? state.data.violations : [];
  const next = state.kind === "loaded" ? state.data.next_cursor : undefined;

  return (
    <div className="flex flex-col gap-4 p-4">
      <PageHeader titleKey="authority.violations_page.title" introKey="authority.violations_page.intro" />
      <form
        className="flex flex-wrap items-end gap-3"
        aria-label={t("authority.common.filters")}
        onSubmit={(e) => {
          e.preventDefault();
          setCursors([]);
          setApplied(draft);
        }}
      >
        <Choice
          name="status"
          labelKey="authority.violations_page.status"
          anyKey="authority.common.any"
          value={draft.status}
          onChange={(status) => setDraft({ ...draft, status })}
          options={VIOLATION_STATUSES.map((s) => ({ value: s, labelKey: `authority.violation.status.${s}` }))}
          testId="filter-status"
        />
        <Choice
          name="kind"
          labelKey="authority.violations_page.kind"
          anyKey="authority.common.any"
          value={draft.kind}
          onChange={(kind) => setDraft({ ...draft, kind })}
          options={VIOLATION_KINDS.map((k) => ({ value: k, labelKey: `authority.violation.kind.${k}` }))}
          testId="filter-kind"
        />
        <TextInput name="from" type="datetime-local" labelKey="authority.violations_page.from" value={draft.from} onChange={(from) => setDraft({ ...draft, from })} />
        <TextInput name="to" type="datetime-local" labelKey="authority.violations_page.to" value={draft.to} onChange={(to) => setDraft({ ...draft, to })} />
        <Button type="submit" data-testid="filter-apply">
          {t("authority.common.apply")}
        </Button>
      </form>
      <LoadNotice state={state} />
      {state.kind === "loaded" && (
        <Table data-testid="violations-table">
          <TableCaption>{t("authority.violations_page.caption")}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>{t("authority.violations_page.opened")}</TableHead>
              <TableHead>{t("authority.violations_page.kind")}</TableHead>
              <TableHead>{t("authority.violations_page.severity")}</TableHead>
              <TableHead>{t("authority.violations_page.status")}</TableHead>
              <TableHead>{t("authority.violations_page.aircraft")}</TableHead>
              <TableHead>{t("authority.violations_page.peak")}</TableHead>
              <TableHead>{t("authority.violations_page.evidence")}</TableHead>
              <TableHead>{t("authority.violations_page.closed")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} data-testid="violations-empty">
                  {t("authority.violations_page.empty")}
                </TableCell>
              </TableRow>
            )}
            {rows.map((v) => (
              <TableRow key={v.violation_id} data-violation-row={v.violation_id}>
                <TableCell>
                  <Link className="underline underline-offset-2" href={consolePath(lang, `/violations/${v.violation_id}`)}>
                    {fmtTimeUTC(v.opened_at, lang, { seconds: true })}
                  </Link>
                </TableCell>
                <TableCell>{t(`authority.violation.kind.${v.kind}`)}</TableCell>
                <TableCell>
                  <Badge variant="outline">{t(`severity.${v.severity}`)}</Badge>
                </TableCell>
                <TableCell>{t(`authority.violation.status.${v.status}`)}</TableCell>
                <TableCell>
                  {t("authority.violations.identity", { serial: v.serial ?? "—", operator: fmtRegistrationNumber(v.operator_reg ?? null) })}
                </TableCell>
                <TableCell>
                  <Peak v={v} />
                </TableCell>
                <TableCell>
                  <TrustWords trust={v.evidence_trust} />
                </TableCell>
                <TableCell>
                  {v.closed_at === null || v.closed_at === undefined
                    ? t("authority.violations_page.open")
                    : t("authority.violations_page.closed_value", {
                        at: fmtTimeUTC(v.closed_at, lang, { seconds: true }),
                        reason: t(`authority.violation.clear.${v.clear_reason ?? "unknown"}`),
                      })}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <div className="flex gap-2">
        <Button type="button" variant="outline" disabled={cursors.length === 0} onClick={() => setCursors(cursors.slice(0, -1))}>
          {t("authority.common.previous")}
        </Button>
        <Button type="button" variant="outline" disabled={next === undefined} onClick={() => next !== undefined && setCursors([...cursors, next])} data-testid="next-page">
          {t("authority.common.next")}
        </Button>
      </div>
    </div>
  );
}
