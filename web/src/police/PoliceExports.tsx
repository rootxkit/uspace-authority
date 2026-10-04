"use client";

// /<locale>/police/exports (police.query): a legal evidence pack of an
// incident, or of the aircraft the picture held in a box over a window
// (api then opens an incident "police_request"), and its download. A
// legal pack carries personal data, so only a personal-data purpose is
// offered; api refuses any other (403 purpose_not_pii) and lets only the
// exporting agency download. The export and each download are recorded
// with the purpose and the case reference.
import { useState } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { fmtNum, fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Button } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { ProblemText } from "../common/Problem";
import { Choice, Facts, PageHeader, Part, TextInput } from "../common/ui";
import { must, useClient } from "../common/useApi";
import { DownloadButton } from "../oversight/incidents/PackDownload";
import { bboxParam, queryBasisProblem } from "./config";
import { BasisFields, type Basis } from "./PoliceQueries";
import { usePoliceConfig } from "./PoliceShell";

type S = components["schemas"];

export function PoliceExports() {
  const t = useT();
  const { lang } = useLang();
  const client = useClient();
  const cfg = usePoliceConfig();
  // A legal pack needs a personal-data purpose: only those are offered.
  const piiPurposes = "config" in cfg ? cfg.config.piiPurposes : [];
  const [basis, setBasis] = useState<Basis>({ purpose: "", caseRef: "" });
  const [target, setTarget] = useState<"incident" | "area">("area");
  const [incidentId, setIncidentId] = useState("");
  const [box, setBox] = useState({ minLng: "", minLat: "", maxLng: "", maxLat: "" });
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [blocked, setBlocked] = useState<string | null>(null);
  const [made, setMade] = useState<{ exp: S["PoliceExport"]; basis: Basis }[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="flex flex-col gap-4 p-4">
      <PageHeader titleKey="authority.police.exports_title" introKey="authority.police.exports_intro" />
      <BasisFields basis={basis} onChange={setBasis} purposes={piiPurposes} piiPurposes={piiPurposes} />
      <Part titleKey="authority.police.export_new" testId="export-new">
        <form
          className="grid gap-3 md:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            const problem = queryBasisProblem(basis.purpose, basis.caseRef, piiPurposes);
            const f = inputToUtc(from);
            const tt = inputToUtc(to);
            const bbox = bboxParam(box.minLng, box.minLat, box.maxLng, box.maxLat);
            const missing =
              problem ?? (f === null || tt === null ? "authority.police.window_missing" : target === "area" && bbox === null ? "authority.police.bbox_missing" : target === "incident" && incidentId.trim() === "" ? "authority.police.incident_missing" : null);
            setBlocked(missing);
            if (missing !== null || f === null || tt === null) return;
            setBusy(true);
            setError(null);
            const sent = { ...basis, caseRef: basis.caseRef.trim() };
            client
              .POST("/v1/police/exports", {
                body: {
                  purpose: sent.purpose,
                  case_ref: sent.caseRef,
                  from: f,
                  to: tt,
                  ...(target === "incident" ? { incident_id: incidentId.trim() } : { query: { bbox: bbox ?? "" } }),
                },
              })
              .then((r) => {
                const exp = must(r);
                setMade((m) => [{ exp, basis: sent }, ...m]);
              })
              .catch((err: unknown) => {
                if (err instanceof ApiError) setError(err);
              })
              .finally(() => setBusy(false));
          }}
        >
          <Choice
            name="target"
            labelKey="authority.police.export_target"
            value={target}
            onChange={(v) => setTarget(v === "incident" ? "incident" : "area")}
            options={[
              { value: "area", labelKey: "authority.police.export_target_area" },
              { value: "incident", labelKey: "authority.police.export_target_incident" },
            ]}
            testId="export-target"
          />
          {target === "incident" ? (
            <TextInput name="incident_id" required labelKey="authority.police.incident_id" value={incidentId} onChange={setIncidentId} testId="export-incident" />
          ) : (
            <div className="grid grid-cols-2 gap-2">
              <TextInput name="min_lng" labelKey="authority.police.bbox.min_lng" value={box.minLng} onChange={(minLng) => setBox({ ...box, minLng })} testId="export-min-lng" />
              <TextInput name="min_lat" labelKey="authority.police.bbox.min_lat" value={box.minLat} onChange={(minLat) => setBox({ ...box, minLat })} testId="export-min-lat" />
              <TextInput name="max_lng" labelKey="authority.police.bbox.max_lng" value={box.maxLng} onChange={(maxLng) => setBox({ ...box, maxLng })} testId="export-max-lng" />
              <TextInput name="max_lat" labelKey="authority.police.bbox.max_lat" value={box.maxLat} onChange={(maxLat) => setBox({ ...box, maxLat })} testId="export-max-lat" />
            </div>
          )}
          <TextInput name="from" type="datetime-local" required labelKey="authority.police.window_from" value={from} onChange={setFrom} testId="export-from" />
          <TextInput name="to" type="datetime-local" required labelKey="authority.police.window_to" value={to} onChange={setTo} testId="export-to" />
          <div className="md:col-span-2">
            <Button type="submit" disabled={busy} data-testid="export-submit">
              {t("authority.police.export_build")}
            </Button>
          </div>
        </form>
        {blocked !== null && (
          <p role="alert" className="m-0 text-sm text-[var(--us-danger)]" data-testid="basis-blocked">
            {t(blocked)}
          </p>
        )}
        {error !== null && <ProblemText error={error} />}
      </Part>
      {made.map(({ exp, basis: b }) => (
        <Part key={exp.pack_id} titleKey="authority.police.export_made" vars={{ id: exp.pack_id }} testId="export-made">
          <Facts
            items={[
              { labelKey: "authority.police.export_incident", value: t(exp.incident_opened ? "authority.police.export_incident_opened" : "authority.police.export_incident_existing", { id: exp.incident_id }) },
              { labelKey: "authority.pack.window", value: t("authority.pack.window_value", { from: fmtTimeUTC(exp.from, lang, { seconds: true }), to: fmtTimeUTC(exp.to, lang, { seconds: true }) }) },
              { labelKey: "authority.pack.hash", value: <span className="font-mono text-xs break-all">{exp.content_hash}</span> },
              { labelKey: "authority.pack.size", value: fmtNum(exp.size_bytes, 0, "B", lang) },
              { labelKey: "authority.pack.signed_by", value: exp.signature_kid ?? t("authority.pack.unsigned") },
              { labelKey: "authority.police.export_basis", value: t("authority.police.meta", { id: exp.query_id, purpose: b.purpose, case_ref: b.caseRef }) },
            ]}
          />
          <DownloadButton
            fileName={`${exp.pack_id}.zip`}
            download={(c) =>
              c.GET("/v1/police/exports/{pack_id}/download", {
                params: { path: { pack_id: exp.pack_id }, query: { purpose: b.purpose, case_ref: b.caseRef } },
                parseAs: "blob",
              })
            }
          />
        </Part>
      ))}
    </div>
  );
}
