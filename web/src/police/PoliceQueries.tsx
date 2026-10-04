"use client";

// /<locale>/police (police.query): who is flying in a box now or was at
// an instant, an operator's registration and fleet, an aircraft by its
// serial. Every query names a purpose from the configured list and the
// agency's case reference, and is not sent without both (the client's
// check; api makes the same one and records every query it answers).
// The operator's identity appears only when api releases it for a
// personal-data purpose, and says that the read was recorded. An empty
// or stale answer says so: it is not an empty sky.
import { useState } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { fmtAge, fmtAltitude, fmtHeading, fmtHeight, fmtNum, fmtRegistrationNumber, fmtSpeed, fmtTimeUTC, useLang, useT, type HeightRef } from "@rootxkit/uspace-ui/i18n";
import { Badge, Button, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../common/Table";
import type { components } from "../api/types";
import { en } from "../i18n/catalogues";
import { ProblemText } from "../common/Problem";
import { Choice, Facts, PageHeader, Part, TextInput } from "../common/ui";
import { must, useClient } from "../common/useApi";
import { TrustWords } from "../oversight/violations/ViolationsList";
import { CASE_REF_MAX, bboxParam, queryBasisProblem } from "./config";
import { usePoliceConfig } from "./PoliceShell";

type S = components["schemas"];

/** A configured purpose, worded when the catalogue knows it and shown as its code otherwise. */
export function purposeOption(code: string): { value: string; labelKey?: string } {
  const key = `authority.police.purpose.${code}`;
  return key in en ? { value: code, labelKey: key } : { value: code };
}

export interface Basis {
  purpose: string;
  caseRef: string;
}

/** The purpose and the case reference, asked once on the page and sent with every query. */
export function BasisFields({ basis, onChange, purposes, piiPurposes }: { basis: Basis; onChange(b: Basis): void; purposes: readonly string[]; piiPurposes: readonly string[] }) {
  const t = useT();
  return (
    <fieldset className="flex flex-wrap items-end gap-3 rounded-md border border-[var(--us-border-strong)] p-3" data-testid="query-basis">
      <legend className="px-1 text-sm font-semibold">{t("authority.police.basis.legend")}</legend>
      <Choice
        name="purpose"
        labelKey="authority.police.basis.purpose"
        anyKey="authority.police.basis.choose"
        required
        value={basis.purpose}
        onChange={(purpose) => onChange({ ...basis, purpose })}
        options={purposes.map((p) => purposeOption(p))}
        testId="basis-purpose"
      />
      <TextInput
        name="case_ref"
        required
        maxLength={CASE_REF_MAX}
        labelKey="authority.police.basis.case_ref"
        hintKey="authority.police.basis.case_ref_hint"
        value={basis.caseRef}
        onChange={(caseRef) => onChange({ ...basis, caseRef })}
        testId="basis-case-ref"
      />
      <p className="m-0 text-xs text-[var(--us-text-muted)]" data-testid="basis-pii">
        {piiPurposes.includes(basis.purpose) ? t("authority.police.basis.pii_yes") : t("authority.police.basis.pii_no")}
      </p>
    </fieldset>
  );
}

function Meta({ meta }: { meta: S["PoliceQueryMeta"] }) {
  const t = useT();
  return (
    <p className="m-0 text-xs text-[var(--us-text-muted)]" data-testid="query-meta" data-pii={String(meta.pii_released)}>
      {t("authority.police.meta", { id: meta.query_id, purpose: meta.purpose, case_ref: meta.case_ref })}{" "}
      {t(meta.pii_released ? "authority.police.meta_pii" : "authority.police.meta_no_pii")}
    </p>
  );
}

/** The operator's identity: personal data, released by api for the purpose and recorded. */
function Identity({ id }: { id: S["PoliceOperatorIdentity"] }) {
  const t = useT();
  return (
    <div className="rounded-md border border-[var(--us-severity-critical)] p-2" data-testid="operator-identity">
      <p className="m-0 text-xs font-semibold">{t("authority.police.identity_note")}</p>
      <Facts
        items={[
          { labelKey: "authority.police.identity.operator_id", value: id.operator_id },
          { labelKey: "authority.police.identity.operator_type", value: id.operator_type },
          ...(id.full_name === undefined ? [] : [{ labelKey: "authority.police.identity.full_name", value: id.full_name }]),
          ...(id.legal_name === undefined ? [] : [{ labelKey: "authority.police.identity.legal_name", value: id.legal_name }]),
          ...(id.postal_address === undefined ? [] : [{ labelKey: "authority.police.identity.postal_address", value: id.postal_address }]),
          ...(id.contact_email === undefined ? [] : [{ labelKey: "authority.police.identity.contact_email", value: id.contact_email }]),
          ...(id.contact_phone === undefined ? [] : [{ labelKey: "authority.police.identity.contact_phone", value: id.contact_phone }]),
        ]}
      />
    </div>
  );
}

function Registration({ r }: { r: S["PoliceRegistration"] }) {
  const { lang } = useLang();
  const t = useT();
  return (
    <Facts
      items={[
        { labelKey: "authority.police.reg.number", value: fmtRegistrationNumber(r.registration_number) },
        { labelKey: "authority.police.reg.type", value: r.operator_type },
        { labelKey: "authority.police.reg.status", value: t(`authority.registry_status.${r.status}`), testId: "reg-status" },
        { labelKey: "authority.police.reg.validity", value: t("authority.pack.window_value", { from: fmtTimeUTC(r.valid_from, lang), to: fmtTimeUTC(r.valid_until, lang) }) },
      ]}
    />
  );
}

function Fleet({ fleet, truncated }: { fleet: readonly S["PoliceUAS"][]; truncated: boolean }) {
  const t = useT();
  return (
    <>
      <Table data-testid="fleet">
        <TableCaption>{t("authority.police.fleet")}</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>{t("authority.police.uas.serial")}</TableHead>
            <TableHead>{t("authority.police.uas.status")}</TableHead>
            <TableHead>{t("authority.police.uas.class")}</TableHead>
            <TableHead>{t("authority.police.uas.model")}</TableHead>
            <TableHead>{t("authority.police.uas.mark")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {fleet.map((u) => (
            <TableRow key={u.serial}>
              <TableCell>{u.serial}</TableCell>
              <TableCell>{t(`authority.registry_status.${u.status}`)}</TableCell>
              <TableCell>{u.class_label ?? "—"}</TableCell>
              <TableCell>{[u.manufacturer, u.model].filter((x) => x !== undefined).join(" ") || "—"}</TableCell>
              <TableCell>{u.registration_mark ?? "—"}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {truncated && <p className="m-0 text-sm">{t("authority.police.fleet_truncated")}</p>}
    </>
  );
}

/**
 * One React key per position row. Two positions may share their time
 * (two sources, a repeated broadcast), so the time alone is not a key;
 * the row's place in api's answer, which never reorders, makes it one.
 */
export function positionRowKeys(positions: readonly { at: string }[]): string[] {
  return positions.map((p, i) => `${i}|${p.at}`);
}

function PositionsTable({ a }: { a: S["PoliceAircraft"] }) {
  const t = useT();
  const { lang } = useLang();
  const keys = positionRowKeys(a.positions);
  return (
    <Table>
      <TableCaption>{t("authority.police.positions", { track: a.track_id })}</TableCaption>
      <TableHeader>
        <TableRow>
          <TableHead>{t("authority.excerpt.captured")}</TableHead>
          <TableHead>{t("authority.excerpt.position")}</TableHead>
          <TableHead>{t("authority.excerpt.altitude")}</TableHead>
          <TableHead>{t("authority.police.height")}</TableHead>
          <TableHead>{t("authority.excerpt.speed")}</TableHead>
          <TableHead>{t("authority.excerpt.track")}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {a.positions.map((p, i) => (
          <TableRow key={keys[i]}>
            <TableCell>{fmtTimeUTC(p.at, lang, { seconds: true })}</TableCell>
            <TableCell className="font-mono">{`${fmtNum(p.lat_deg, 6)}, ${fmtNum(p.lon_deg, 6)}`}</TableCell>
            <TableCell>{p.alt_source === "pressure" ? fmtAltitude(null, "pressure", lang) : fmtAltitude(p.alt_amsl_m ?? null, "AMSL", lang)}</TableCell>
            <TableCell>{fmtHeight(p.height_m ?? null, (p.height_ref ?? null) as HeightRef | null, lang)}</TableCell>
            <TableCell>{fmtSpeed(p.speed_ms ?? null, lang)}</TableCell>
            <TableCell>{fmtHeading(p.track_deg ?? null)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function AircraftAnswer({ r }: { r: S["PoliceAircraftAnswer"] }) {
  const t = useT();
  const { lang } = useLang();
  return (
    <div className="flex flex-col gap-3" data-testid="aircraft-answer" data-count={r.aircraft.length}>
      <Meta meta={r} />
      <p className="m-0 text-sm">
        {t(r.mode === "live" ? "authority.police.mode_live" : "authority.police.mode_at", {
          as_of: fmtTimeUTC(r.as_of, lang, { seconds: true }),
          from: fmtTimeUTC(r.window_from, lang, { seconds: true }),
          to: fmtTimeUTC(r.window_to, lang, { seconds: true }),
        })}
      </p>
      <p className={r.sources.degraded ? "m-0 text-sm text-[var(--us-danger)]" : "m-0 text-sm"} role={r.sources.degraded ? "alert" : undefined} data-testid="picture-sources" data-degraded={String(r.sources.degraded)}>
        {t(r.sources.degraded ? "authority.police.sources_degraded" : "authority.police.sources_ok", {
          age: fmtAge(r.sources.newest_track_age_s ?? null, lang),
          gaps: r.sources.writer_gaps,
          causes: r.sources.writer_gap_causes.join(", ") || "—",
        })}
      </p>
      {r.truncated && (
        <p role="status" className="m-0 text-sm" data-testid="aircraft-truncated">
          {t("authority.police.aircraft_truncated")}
        </p>
      )}
      {r.aircraft.length === 0 && (
        <p className="m-0 text-sm" data-testid="aircraft-empty">
          {t("authority.police.aircraft_empty")}
        </p>
      )}
      {r.aircraft.map((a) => (
        <div key={a.track_id} className="flex flex-col gap-2 rounded-md border border-[var(--us-border)] p-2" data-police-track={a.track_id}>
          <Facts
            items={[
              { labelKey: "authority.police.aircraft.track", value: <span className="font-mono text-xs">{a.track_id}</span> },
              { labelKey: "authority.police.aircraft.serial", value: a.serial ?? "—" },
              { labelKey: "authority.police.aircraft.registration", value: fmtRegistrationNumber(a.registration_number ?? null) },
              {
                labelKey: "authority.police.aircraft.identification",
                value: t("authority.police.aircraft.identification_value", {
                  status: t(`ident.status.${a.identification_status}`),
                  reason: a.identification_reason ?? "—",
                  basis: a.identification_basis,
                }),
              },
              { labelKey: "authority.police.aircraft.trust", value: <TrustWords trust={a.trust} /> },
              { labelKey: "authority.police.aircraft.source", value: a.source },
              { labelKey: "authority.police.aircraft.seen", value: t("authority.pack.window_value", { from: fmtTimeUTC(a.first_seen, lang, { seconds: true }), to: fmtTimeUTC(a.last_seen, lang, { seconds: true }) }) },
              { labelKey: "authority.police.aircraft.emergency", value: a.emergency ? <Badge variant="destructive">{t("authority.common.yes")}</Badge> : t("authority.common.no") },
            ]}
          />
          {a.operator !== undefined && <Identity id={a.operator} />}
          {a.operator_unresolved !== undefined && (
            <p className="m-0 text-sm" data-testid="operator-unresolved">
              {t("authority.police.operator_unresolved", { reason: t(`authority.police.unresolved.${a.operator_unresolved}`) })}
            </p>
          )}
          <PositionsTable a={a} />
          {a.positions_truncated && <p className="m-0 text-xs">{t("authority.police.positions_truncated")}</p>}
        </div>
      ))}
    </div>
  );
}

type Answer = { kind: "aircraft"; data: S["PoliceAircraftAnswer"] } | { kind: "operator"; data: S["PoliceOperatorAnswer"] } | { kind: "serial"; data: S["PoliceSerialAnswer"] };

export function PoliceQueries() {
  const t = useT();
  const client = useClient();
  const cfg = usePoliceConfig();
  const purposes = "config" in cfg ? cfg.config.purposes : [];
  const piiPurposes = "config" in cfg ? cfg.config.piiPurposes : [];
  const [basis, setBasis] = useState<Basis>({ purpose: "", caseRef: "" });
  const [box, setBox] = useState({ minLng: "", minLat: "", maxLng: "", maxLat: "" });
  const [at, setAt] = useState("");
  const [reg, setReg] = useState("");
  const [serial, setSerial] = useState("");
  const [blocked, setBlocked] = useState<string | null>(null);
  const [answer, setAnswer] = useState<Answer | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  /** The client's check of the basis; null when the query may go. */
  const check = (): { purpose: string; case_ref: string } | null => {
    const problem = queryBasisProblem(basis.purpose, basis.caseRef, purposes);
    setBlocked(problem);
    return problem === null ? { purpose: basis.purpose, case_ref: basis.caseRef.trim() } : null;
  };
  const run = (p: Promise<Answer>) => {
    setBusy(true);
    setError(null);
    setAnswer(null);
    p.then(setAnswer)
      .catch((err: unknown) => {
        if (err instanceof ApiError) setError(err);
      })
      .finally(() => setBusy(false));
  };

  return (
    <div className="flex flex-col gap-4 p-4">
      <PageHeader titleKey="authority.police.queries_title" introKey="authority.police.queries_intro" />
      <BasisFields basis={basis} onChange={setBasis} purposes={purposes} piiPurposes={piiPurposes} />
      {blocked !== null && (
        <p role="alert" className="m-0 text-sm text-[var(--us-danger)]" data-testid="basis-blocked">
          {t(blocked)}
        </p>
      )}
      <div className="grid gap-4 lg:grid-cols-3">
        <Part titleKey="authority.police.q_aircraft" testId="q-aircraft">
          <form
            className="flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              const b = check();
              const bbox = bboxParam(box.minLng, box.minLat, box.maxLng, box.maxLat);
              if (b === null) return;
              if (bbox === null) {
                setBlocked("authority.police.bbox_missing");
                return;
              }
              const when = at === "" ? null : inputToUtc(at);
              run(
                client
                  .GET("/v1/police/aircraft", { params: { query: { bbox, ...b, ...(when === null ? {} : { at: when }) } } })
                  .then((r) => ({ kind: "aircraft" as const, data: must(r) })),
              );
            }}
          >
            <div className="grid grid-cols-2 gap-2">
              <TextInput name="min_lng" labelKey="authority.police.bbox.min_lng" value={box.minLng} onChange={(minLng) => setBox({ ...box, minLng })} testId="bbox-min-lng" />
              <TextInput name="min_lat" labelKey="authority.police.bbox.min_lat" value={box.minLat} onChange={(minLat) => setBox({ ...box, minLat })} testId="bbox-min-lat" />
              <TextInput name="max_lng" labelKey="authority.police.bbox.max_lng" value={box.maxLng} onChange={(maxLng) => setBox({ ...box, maxLng })} testId="bbox-max-lng" />
              <TextInput name="max_lat" labelKey="authority.police.bbox.max_lat" value={box.maxLat} onChange={(maxLat) => setBox({ ...box, maxLat })} testId="bbox-max-lat" />
            </div>
            <TextInput name="at" type="datetime-local" labelKey="authority.police.at" hintKey="authority.police.at_hint" value={at} onChange={setAt} />
            <Button type="submit" disabled={busy} data-testid="q-aircraft-submit">
              {t("authority.police.ask")}
            </Button>
          </form>
        </Part>
        <Part titleKey="authority.police.q_operator" testId="q-operator">
          <form
            className="flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              const b = check();
              if (b === null || reg.trim() === "") return;
              run(
                client
                  .GET("/v1/police/operators/{reg}", { params: { path: { reg: reg.trim() }, query: b } })
                  .then((r) => ({ kind: "operator" as const, data: must(r) })),
              );
            }}
          >
            <TextInput name="reg" required maxLength={64} labelKey="authority.police.reg_number" hintKey="authority.police.reg_number_hint" value={reg} onChange={setReg} testId="q-operator-reg" />
            <Button type="submit" disabled={busy} data-testid="q-operator-submit">
              {t("authority.police.ask")}
            </Button>
          </form>
        </Part>
        <Part titleKey="authority.police.q_serial" testId="q-serial">
          <form
            className="flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              const b = check();
              if (b === null || serial.trim() === "") return;
              run(
                client
                  .GET("/v1/police/serials/{serial}", { params: { path: { serial: serial.trim() }, query: b } })
                  .then((r) => ({ kind: "serial" as const, data: must(r) })),
              );
            }}
          >
            <TextInput name="serial" required maxLength={64} labelKey="authority.police.serial" value={serial} onChange={setSerial} testId="q-serial-input" />
            <Button type="submit" disabled={busy} data-testid="q-serial-submit">
              {t("authority.police.ask")}
            </Button>
          </form>
        </Part>
      </div>
      {error !== null && <ProblemText error={error} />}
      {answer !== null && (
        <Part titleKey="authority.police.answer" testId="police-answer">
          {answer.kind === "aircraft" && <AircraftAnswer r={answer.data} />}
          {answer.kind === "operator" && (
            <div className="flex flex-col gap-2" data-testid="operator-answer">
              <Meta meta={answer.data} />
              <Registration r={answer.data.operator} />
              {answer.data.identity !== undefined && <Identity id={answer.data.identity} />}
              <Fleet fleet={answer.data.fleet} truncated={answer.data.fleet_truncated} />
            </div>
          )}
          {answer.kind === "serial" && (
            <div className="flex flex-col gap-2" data-testid="serial-answer">
              <Meta meta={answer.data} />
              <Facts
                items={[
                  { labelKey: "authority.police.uas.serial", value: answer.data.uas.serial },
                  { labelKey: "authority.police.uas.status", value: t(`authority.registry_status.${answer.data.uas.status}`) },
                ]}
              />
              <Registration r={answer.data.operator} />
              {answer.data.identity !== undefined && <Identity id={answer.data.identity} />}
            </div>
          )}
        </Part>
      )}
    </div>
  );
}
