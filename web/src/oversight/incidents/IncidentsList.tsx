"use client";

// /<locale>/incidents (inspector, incident_officer): the case list with
// its filters, and opening a case from the authority's own observation
// or an ANSP's or a USSP's notice. A case is opened from a violation
// only by escalating it, and never from an occurrence report (376/2014
// Art. 15-16): this form offers neither.
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Badge, Button, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../../common/Table";
import type { components } from "../../api/types";
import { LoadNotice, ProblemText } from "../../common/Problem";
import { Choice, PageHeader, Part, TextInput } from "../../common/ui";
import { must, useClient, useLoad } from "../../common/useApi";
import { consolePath } from "../../shell/paths";
import { INCIDENT_KINDS, INCIDENT_OPENED_BY_HAND, INCIDENT_SEVERITIES, INCIDENT_STATUSES } from "../enums";

type S = components["schemas"];

const PAGE_LIMIT = 50;

function OpenIncident() {
  const t = useT();
  const { lang } = useLang();
  const client = useClient();
  const router = useRouter();
  const [kind, setKind] = useState<string>("other");
  const [openedFrom, setOpenedFrom] = useState<string>("own_observation");
  const [severity, setSeverity] = useState<string>("warning");
  const [occurredAt, setOccurredAt] = useState("");
  const [noticeRef, setNoticeRef] = useState("");
  const [narrative, setNarrative] = useState("");
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const notice = openedFrom !== "own_observation";
  return (
    <form
      className="grid gap-3 md:grid-cols-2"
      data-testid="incident-create"
      onSubmit={(e) => {
        e.preventDefault();
        const at = inputToUtc(occurredAt);
        if (at === null) return;
        setBusy(true);
        setError(null);
        client
          .POST("/v1/incidents", {
            body: {
              kind: kind as S["IncidentKind"],
              opened_from: openedFrom as S["IncidentOpenedFrom"],
              severity: severity as S["IncidentSeverity"],
              occurred_at: at,
              ...(notice && noticeRef.trim() !== "" ? { notice_ref: noticeRef.trim() } : {}),
              ...(narrative.trim() === "" ? {} : { narrative }),
            },
          })
          .then((r) => router.push(consolePath(lang, `/incidents/${must(r).incident_id}`)))
          .catch((err: unknown) => {
            if (err instanceof ApiError) setError(err);
          })
          .finally(() => setBusy(false));
      }}
    >
      <Choice name="kind" labelKey="authority.incidents.kind" value={kind} onChange={setKind} options={INCIDENT_KINDS.map((k) => ({ value: k, labelKey: `authority.incident.kind.${k}` }))} />
      <Choice
        name="opened_from"
        labelKey="authority.incidents.opened_from"
        value={openedFrom}
        onChange={setOpenedFrom}
        options={INCIDENT_OPENED_BY_HAND.map((k) => ({ value: k, labelKey: `authority.incident.opened_from.${k}` }))}
      />
      <Choice
        name="severity"
        labelKey="authority.incidents.severity"
        value={severity}
        onChange={setSeverity}
        options={INCIDENT_SEVERITIES.map((k) => ({ value: k, labelKey: `severity.${k}` }))}
      />
      <TextInput name="occurred_at" type="datetime-local" required labelKey="authority.incidents.occurred_at" value={occurredAt} onChange={setOccurredAt} />
      {notice && <TextInput name="notice_ref" required maxLength={200} labelKey="authority.incidents.notice_ref" value={noticeRef} onChange={setNoticeRef} />}
      <div className="md:col-span-2">
        <TextInput name="narrative" multiline maxLength={20000} labelKey="authority.incidents.narrative" value={narrative} onChange={setNarrative} />
      </div>
      {error !== null && (
        <div className="md:col-span-2">
          <ProblemText error={error} />
        </div>
      )}
      <div>
        <Button type="submit" disabled={busy} data-testid="incident-create-submit">
          {t("authority.incidents.open")}
        </Button>
      </div>
    </form>
  );
}

export function IncidentsList() {
  const t = useT();
  const { lang } = useLang();
  const [status, setStatus] = useState("");
  const [kind, setKind] = useState("");
  const [cursors, setCursors] = useState<string[]>([]);
  const cursor = cursors.at(-1);
  const { state } = useLoad(JSON.stringify({ status, kind, cursor }), async (c) =>
    must(
      await c.GET("/v1/incidents", {
        params: {
          query: {
            limit: PAGE_LIMIT,
            ...(status === "" ? {} : { status: status as S["IncidentStatus"] }),
            ...(kind === "" ? {} : { kind: kind as S["IncidentKind"] }),
            ...(cursor === undefined ? {} : { cursor }),
          },
        },
      }),
    ),
  );
  const rows = state.kind === "loaded" ? state.data.incidents : [];
  const next = state.kind === "loaded" ? state.data.next_cursor : undefined;
  return (
    <div className="flex flex-col gap-4 p-4">
      <PageHeader titleKey="authority.incidents.title" introKey="authority.incidents.intro" />
      <div className="flex flex-wrap items-end gap-3">
        <Choice
          name="status"
          labelKey="authority.incidents.status"
          anyKey="authority.common.any"
          value={status}
          onChange={(v) => {
            setCursors([]);
            setStatus(v);
          }}
          options={INCIDENT_STATUSES.map((s) => ({ value: s, labelKey: `authority.incident.status.${s}` }))}
        />
        <Choice
          name="kind"
          labelKey="authority.incidents.kind"
          anyKey="authority.common.any"
          value={kind}
          onChange={(v) => {
            setCursors([]);
            setKind(v);
          }}
          options={INCIDENT_KINDS.map((k) => ({ value: k, labelKey: `authority.incident.kind.${k}` }))}
        />
      </div>
      <LoadNotice state={state} />
      {state.kind === "loaded" && (
        <Table data-testid="incidents-table">
          <TableCaption>{t("authority.incidents.caption")}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>{t("authority.incidents.occurred_at")}</TableHead>
              <TableHead>{t("authority.incidents.kind")}</TableHead>
              <TableHead>{t("authority.incidents.severity")}</TableHead>
              <TableHead>{t("authority.incidents.status")}</TableHead>
              <TableHead>{t("authority.incidents.opened_from")}</TableHead>
              <TableHead>{t("authority.incidents.assignee")}</TableHead>
              <TableHead>{t("authority.incidents.updated_at")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={7}>{t("authority.incidents.empty")}</TableCell>
              </TableRow>
            )}
            {rows.map((i) => (
              <TableRow key={i.incident_id} data-incident-row={i.incident_id}>
                <TableCell>
                  <Link className="underline underline-offset-2" href={consolePath(lang, `/incidents/${i.incident_id}`)}>
                    {fmtTimeUTC(i.occurred_at, lang)}
                  </Link>
                </TableCell>
                <TableCell>{t(`authority.incident.kind.${i.kind}`)}</TableCell>
                <TableCell>
                  <Badge variant="outline">{t(`severity.${i.severity}`)}</Badge>
                </TableCell>
                <TableCell>{t(`authority.incident.status.${i.status}`)}</TableCell>
                <TableCell>{t(`authority.incident.opened_from.${i.opened_from}`)}</TableCell>
                <TableCell>{i.assignee ?? "—"}</TableCell>
                <TableCell>{fmtTimeUTC(i.updated_at, lang)}</TableCell>
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
      <Part titleKey="authority.incidents.open_title">
        <OpenIncident />
      </Part>
    </div>
  );
}
