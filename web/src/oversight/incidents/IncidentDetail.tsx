"use client";

// /<locale>/incidents/<id> (inspector, incident_officer): the case file,
// its aircraft, its notes (append-only), and its evidence packs: build
// one for a window with a purpose (and a case reference for a legal
// pack), view its manifest section by section, its hash and signature,
// download it with a purpose, and have api verify it. Every act is
// api's, recorded there with the actor and the purpose; the page shows
// what api answered, a refusal included.
import Link from "next/link";
import { useState } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { fmtNum, fmtRegistrationNumber, fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Badge, Button, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../../common/Table";
import type { components } from "../../api/types";
import { LoadNotice, ProblemText } from "../../common/Problem";
import { Choice, Facts, PageHeader, Part, TextInput } from "../../common/ui";
import { must, useClient, useLoad } from "../../common/useApi";
import { consolePath } from "../../shell/paths";
import { INCIDENT_SEVERITIES, INCIDENT_STATUSES, PACK_KINDS } from "../enums";
import { PackDownload } from "./PackDownload";
import { Manifest } from "./Manifest";

type S = components["schemas"];
type Incident = S["Incident"];

/** Sends one PATCH and hands back the incident as changed. */
function usePatch(id: string, onDone: (i: Incident) => void) {
  const client = useClient();
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const send = (body: S["IncidentPatch"], after?: () => void) => {
    setBusy(true);
    setError(null);
    client
      .PATCH("/v1/incidents/{incident_id}", { params: { path: { incident_id: id } }, body })
      .then((r) => {
        onDone(must(r));
        after?.();
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError) setError(err);
      })
      .finally(() => setBusy(false));
  };
  return { send, error, busy };
}

function CaseControls({ inc, onDone }: { inc: Incident; onDone(i: Incident): void }) {
  const t = useT();
  const [status, setStatus] = useState<string>(inc.status);
  const [assignee, setAssignee] = useState(inc.assignee ?? "");
  const [severity, setSeverity] = useState<string>(inc.severity);
  const { send, error, busy } = usePatch(inc.incident_id, onDone);
  return (
    <form
      className="flex flex-wrap items-end gap-3"
      data-testid="case-controls"
      onSubmit={(e) => {
        e.preventDefault();
        const body: S["IncidentPatch"] = {};
        if (status !== inc.status) body.status = status as S["IncidentStatus"];
        if (assignee.trim() !== "" && assignee.trim() !== (inc.assignee ?? "")) body.assignee = assignee.trim();
        if (severity !== inc.severity) body.severity = severity as S["IncidentSeverity"];
        send(body);
      }}
    >
      <Choice name="status" labelKey="authority.incidents.status" value={status} onChange={setStatus} options={INCIDENT_STATUSES.map((s) => ({ value: s, labelKey: `authority.incident.status.${s}` }))} />
      <TextInput name="assignee" labelKey="authority.incidents.assignee" hintKey="authority.incident_detail.assignee_hint" maxLength={128} value={assignee} onChange={setAssignee} required={status === "assigned"} />
      <Choice name="severity" labelKey="authority.incidents.severity" value={severity} onChange={setSeverity} options={INCIDENT_SEVERITIES.map((s) => ({ value: s, labelKey: `severity.${s}` }))} />
      <Button type="submit" disabled={busy} data-testid="case-save">
        {t("authority.common.save")}
      </Button>
      {error !== null && <ProblemText error={error} />}
    </form>
  );
}

function Aircraft({ inc, onDone }: { inc: Incident; onDone(i: Incident): void }) {
  const t = useT();
  const { lang } = useLang();
  const [serial, setSerial] = useState("");
  const [reg, setReg] = useState("");
  const [tracks, setTracks] = useState("");
  const { send, error, busy } = usePatch(inc.incident_id, onDone);
  return (
    <Part titleKey="authority.incident_detail.aircraft" testId="incident-aircraft">
      <Table>
        <TableCaption>{t("authority.incident_detail.aircraft_caption")}</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>{t("authority.incident_detail.serial")}</TableHead>
            <TableHead>{t("authority.incident_detail.operator_reg")}</TableHead>
            <TableHead>{t("authority.incident_detail.tracks")}</TableHead>
            <TableHead>{t("authority.incident_detail.identification")}</TableHead>
            <TableHead>{t("authority.incident_detail.added")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {inc.aircraft.length === 0 && (
            <TableRow>
              <TableCell colSpan={5}>{t("authority.incident_detail.no_aircraft")}</TableCell>
            </TableRow>
          )}
          {inc.aircraft.map((a) => (
            <TableRow key={a.id}>
              <TableCell>{a.serial ?? "—"}</TableCell>
              <TableCell>{fmtRegistrationNumber(a.operator_reg ?? null)}</TableCell>
              <TableCell className="font-mono text-xs">{a.track_ids.join(", ")}</TableCell>
              <TableCell>
                {a.identification.status === undefined
                  ? "—"
                  : t("authority.incident_detail.identification_value", {
                      status: a.identification.status,
                      reason: a.identification.reason ?? "—",
                      trust: a.identification.evidence_trust ?? "—",
                    })}
              </TableCell>
              <TableCell>{t("authority.incident_detail.added_value", { who: a.added_by, at: fmtTimeUTC(a.added_at, lang) })}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          const trackIds = tracks
            .split(",")
            .map((s) => s.trim())
            .filter((s) => s !== "");
          const one: S["IncidentAircraftInput"] = {
            ...(serial.trim() === "" ? {} : { serial: serial.trim() }),
            ...(reg.trim() === "" ? {} : { operator_reg: reg.trim() }),
            ...(trackIds.length === 0 ? {} : { track_ids: trackIds }),
          };
          send({ add_aircraft: [one] }, () => {
            setSerial("");
            setReg("");
            setTracks("");
          });
        }}
      >
        <TextInput name="serial" labelKey="authority.incident_detail.serial" maxLength={64} value={serial} onChange={setSerial} />
        <TextInput name="operator_reg" labelKey="authority.incident_detail.operator_reg" hintKey="authority.incident_detail.operator_reg_hint" maxLength={64} value={reg} onChange={setReg} />
        <TextInput name="track_ids" labelKey="authority.incident_detail.tracks" hintKey="authority.incident_detail.tracks_hint" value={tracks} onChange={setTracks} />
        <Button type="submit" disabled={busy}>
          {t("authority.incident_detail.add_aircraft")}
        </Button>
      </form>
      {error !== null && <ProblemText error={error} />}
    </Part>
  );
}

function Notes({ inc, onDone }: { inc: Incident; onDone(i: Incident): void }) {
  const t = useT();
  const { lang } = useLang();
  const [note, setNote] = useState("");
  const { send, error, busy } = usePatch(inc.incident_id, onDone);
  return (
    <Part titleKey="authority.incident_detail.notes" testId="incident-notes">
      {inc.notes.length === 0 && <p className="m-0 text-sm">{t("authority.incident_detail.no_notes")}</p>}
      <ol className="m-0 flex flex-col gap-2 ps-5">
        {inc.notes.map((n) => (
          <li key={n.id} data-note={n.id}>
            <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("authority.incident_detail.note_by", { who: n.author, at: fmtTimeUTC(n.created_at, lang) })}</p>
            <p className="m-0 whitespace-pre-wrap text-sm">{n.body}</p>
          </li>
        ))}
      </ol>
      <form
        className="flex flex-col gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (note.trim() === "") return;
          send({ note: note.trim() }, () => setNote(""));
        }}
      >
        <TextInput name="note" multiline required maxLength={4000} labelKey="authority.incident_detail.note" hintKey="authority.incident_detail.note_hint" value={note} onChange={setNote} testId="note-input" />
        <div>
          <Button type="submit" disabled={busy} data-testid="note-submit">
            {t("authority.incident_detail.add_note")}
          </Button>
        </div>
      </form>
      {error !== null && <ProblemText error={error} />}
    </Part>
  );
}

function BuildPack({ inc, onBuilt }: { inc: Incident; onBuilt(p: S["EvidencePack"]): void }) {
  const t = useT();
  const client = useClient();
  const [kind, setKind] = useState<string>("oversight");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [purpose, setPurpose] = useState("");
  const [caseRef, setCaseRef] = useState("");
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const legal = kind === "legal";
  return (
    <form
      className="grid gap-3 md:grid-cols-2"
      data-testid="pack-create"
      onSubmit={(e) => {
        e.preventDefault();
        const f = inputToUtc(from);
        const tt = inputToUtc(to);
        if (f === null || tt === null || purpose.trim() === "" || (legal && caseRef.trim() === "")) return;
        setBusy(true);
        setError(null);
        client
          .POST("/v1/incidents/{incident_id}/evidence-packs", {
            params: { path: { incident_id: inc.incident_id } },
            body: { kind: kind as S["EvidencePackKind"], from: f, to: tt, purpose: purpose.trim(), ...(legal ? { case_ref: caseRef.trim() } : {}) },
          })
          .then((r) => onBuilt(must(r)))
          .catch((err: unknown) => {
            if (err instanceof ApiError) setError(err);
          })
          .finally(() => setBusy(false));
      }}
    >
      <Choice name="kind" labelKey="authority.pack.kind" value={kind} onChange={setKind} options={PACK_KINDS.map((k) => ({ value: k, labelKey: `authority.pack.kind.${k}` }))} testId="pack-kind" />
      <p className="m-0 self-end text-xs text-[var(--us-text-muted)]">{t(legal ? "authority.pack.legal_hint" : "authority.pack.oversight_hint")}</p>
      <TextInput name="from" type="datetime-local" required labelKey="authority.pack.from" value={from} onChange={setFrom} testId="pack-from" />
      <TextInput name="to" type="datetime-local" required labelKey="authority.pack.to" value={to} onChange={setTo} testId="pack-to" />
      <TextInput name="purpose" required maxLength={200} labelKey="authority.pack.purpose" hintKey="authority.pack.purpose_hint" value={purpose} onChange={setPurpose} testId="pack-purpose" />
      {legal && <TextInput name="case_ref" required maxLength={200} labelKey="authority.pack.case_ref" value={caseRef} onChange={setCaseRef} testId="pack-case-ref" />}
      {error !== null && (
        <div className="md:col-span-2">
          <ProblemText error={error} />
        </div>
      )}
      <div>
        <Button type="submit" disabled={busy} data-testid="pack-create-submit">
          {t("authority.pack.build")}
        </Button>
      </div>
    </form>
  );
}

function Verify({ incidentId, packId }: { incidentId: string; packId: string }) {
  const t = useT();
  const { lang } = useLang();
  const client = useClient();
  const [result, setResult] = useState<S["EvidencePackVerification"] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  return (
    <div className="flex flex-col gap-1" data-testid="pack-verify">
      <div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            setError(null);
            client
              .GET("/v1/incidents/{incident_id}/evidence-packs/{pack_id}/verify", { params: { path: { incident_id: incidentId, pack_id: packId } } })
              .then((r) => setResult(must(r)))
              .catch((err: unknown) => {
                if (err instanceof ApiError) setError(err);
              });
          }}
          data-testid="pack-verify-run"
        >
          {t("authority.pack.verify")}
        </Button>
      </div>
      {error !== null && <ProblemText error={error} />}
      {result !== null && (
        <Facts
          testId="pack-verification"
          items={[
            {
              labelKey: "authority.pack.hash_matches",
              value: t(result.hash_matches ? "authority.pack.hash_matches_yes" : "authority.pack.hash_matches_no"),
              testId: "pack-hash-matches",
            },
            { labelKey: "authority.pack.recomputed", value: <span className="font-mono text-xs">{result.recomputed_hash ?? "—"}</span> },
            ...(result.problem === null || result.problem === undefined ? [] : [{ labelKey: "authority.pack.problem", value: result.problem }]),
            { labelKey: "authority.pack.signature", value: t(`authority.pack.signature.${result.signature}`), testId: "pack-signature" },
            ...(result.signature_detail === null || result.signature_detail === undefined ? [] : [{ labelKey: "authority.pack.signature_detail", value: result.signature_detail }]),
            { labelKey: "authority.pack.verified_at", value: fmtTimeUTC(result.verified_at, lang, { seconds: true }) },
          ]}
        />
      )}
    </div>
  );
}

function Packs({ inc, onBuilt }: { inc: Incident; onBuilt(): void }) {
  const t = useT();
  const { lang } = useLang();
  const [built, setBuilt] = useState<S["EvidencePack"] | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Part titleKey="authority.incident_detail.packs" testId="incident-packs">
      {inc.evidence_packs.length === 0 && <p className="m-0 text-sm">{t("authority.incident_detail.no_packs")}</p>}
      <ul className="m-0 flex flex-col gap-3 p-0">
        {inc.evidence_packs.map((p) => (
          <li key={p.pack_id} className="list-none rounded-md border border-[var(--us-border)] p-2" data-pack={p.pack_id}>
            <Facts
              items={[
                { labelKey: "authority.pack.kind", value: <Badge variant="outline">{t(`authority.pack.kind.${p.kind}`)}</Badge> },
                { labelKey: "authority.pack.window", value: t("authority.pack.window_value", { from: fmtTimeUTC(p.from, lang, { seconds: true }), to: fmtTimeUTC(p.to, lang, { seconds: true }) }) },
                { labelKey: "authority.pack.hash", value: <span className="font-mono text-xs break-all">{p.content_hash}</span>, testId: "pack-hash" },
                { labelKey: "authority.pack.size", value: fmtNum(p.size_bytes, 0, "B", lang) },
                { labelKey: "authority.pack.signed_by", value: p.signature_kid ?? t("authority.pack.unsigned") },
                { labelKey: "authority.pack.created", value: t("authority.incident_detail.added_value", { who: p.created_by, at: fmtTimeUTC(p.created_at, lang) }) },
              ]}
            />
            <div className="mt-2 flex flex-wrap gap-4">
              <Button type="button" variant="outline" size="sm" onClick={() => setOpen(open === p.pack_id ? null : p.pack_id)} data-testid="pack-manifest-toggle">
                {t(open === p.pack_id ? "authority.pack.manifest_hide" : "authority.pack.manifest_show")}
              </Button>
            </div>
            {open === p.pack_id && <Manifest incidentId={inc.incident_id} packId={p.pack_id} />}
            <Verify incidentId={inc.incident_id} packId={p.pack_id} />
            <PackDownload
              recordedHash={p.content_hash}
              fileName={`${p.pack_id}.zip`}
              download={(client, purpose) =>
                client.GET("/v1/incidents/{incident_id}/evidence-packs/{pack_id}/download", {
                  params: { path: { incident_id: inc.incident_id, pack_id: p.pack_id }, query: { purpose } },
                  parseAs: "blob",
                })
              }
            />
          </li>
        ))}
      </ul>
      {built !== null && (
        <p role="status" className="m-0 text-sm" data-testid="pack-built">
          {t("authority.pack.built", { hash: built.content_hash })}
        </p>
      )}
      <BuildPack
        inc={inc}
        onBuilt={(p) => {
          setBuilt(p);
          onBuilt();
        }}
      />
    </Part>
  );
}

export function IncidentDetail({ id }: { id: string }) {
  const t = useT();
  const { lang } = useLang();
  const { state, reload } = useLoad(`incident:${id}`, async (c) => must(await c.GET("/v1/incidents/{incident_id}", { params: { path: { incident_id: id } } })));
  const [changed, setChanged] = useState<Incident | null>(null);
  if (state.kind !== "loaded") {
    return (
      <div className="p-4">
        <LoadNotice state={state} />
      </div>
    );
  }
  const inc = changed !== null && changed.updated_at >= state.data.updated_at ? changed : state.data;
  return (
    <div className="flex flex-col gap-4 p-4" data-testid="incident-detail" data-status={inc.status}>
      <PageHeader titleKey="authority.incident_detail.title" vars={{ kind: t(`authority.incident.kind.${inc.kind}`) }}>
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline">{t(`severity.${inc.severity}`)}</Badge>
          <Badge variant="outline" data-testid="incident-status">
            {t(`authority.incident.status.${inc.status}`)}
          </Badge>
        </div>
      </PageHeader>
      <Part titleKey="authority.incident_detail.case_file">
        <Facts
          items={[
            { labelKey: "authority.incident_detail.id", value: <span className="font-mono">{inc.incident_id}</span> },
            { labelKey: "authority.incidents.occurred_at", value: fmtTimeUTC(inc.occurred_at, lang, { seconds: true }) },
            { labelKey: "authority.incidents.opened_from", value: t(`authority.incident.opened_from.${inc.opened_from}`) },
            {
              labelKey: "authority.incident_detail.source_violation",
              value:
                inc.source_violation_id === null || inc.source_violation_id === undefined ? (
                  "—"
                ) : (
                  <Link className="underline underline-offset-2" href={consolePath(lang, `/violations/${inc.source_violation_id}`)}>
                    {inc.source_violation_id}
                  </Link>
                ),
            },
            { labelKey: "authority.incidents.notice_ref", value: inc.notice_ref ?? "—" },
            { labelKey: "authority.incident_detail.intent_refs", value: inc.intent_refs.length === 0 ? "—" : inc.intent_refs.join(", ") },
            { labelKey: "authority.incidents.assignee", value: inc.assignee ?? "—" },
            { labelKey: "authority.incident_detail.opened_by", value: t("authority.incident_detail.added_value", { who: inc.opened_by, at: fmtTimeUTC(inc.created_at, lang) }) },
            { labelKey: "authority.incident_detail.closed_at", value: inc.closed_at === null || inc.closed_at === undefined ? "—" : fmtTimeUTC(inc.closed_at, lang) },
          ]}
        />
        {inc.narrative !== "" && <p className="m-0 whitespace-pre-wrap text-sm">{inc.narrative}</p>}
        <CaseControls key={inc.updated_at} inc={inc} onDone={setChanged} />
      </Part>
      <Aircraft inc={inc} onDone={setChanged} />
      <Notes inc={inc} onDone={setChanged} />
      <Packs
        inc={inc}
        onBuilt={() => {
          setChanged(null);
          reload();
        }}
      />
    </div>
  );
}
