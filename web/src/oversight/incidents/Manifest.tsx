"use client";

// An evidence pack's manifest as api returns it (evidence-pack/v1,
// docs/runbooks/incidents.md): every section with its state, basis and
// reason (a source that could not be read is "unavailable" with the
// reason, never missing), how the tracks were cut and how many holes
// each has, every height over the ground with the ground it rests on,
// and every file with its SHA-256. The manifest holds no personal data.
// It is read defensively: api types it as an object.
import { fmtAltitude, fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../../common/Table";
import { LoadNotice } from "../../common/Problem";
import { Facts } from "../../common/ui";
import { must, useLoad } from "../../common/useApi";

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): Obj[] => (Array.isArray(v) ? v.map(obj) : []);
const str = (v: unknown): string => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "—");

export function ManifestView({ manifest, seal, signatureKid, purpose, caseRef }: { manifest: Obj; seal: Obj; signatureKid: string | null; purpose: string; caseRef: string | null }) {
  const t = useT();
  const { lang } = useLang();
  const sections = Object.entries(obj(manifest["sections"])).sort(([a], [b]) => a.localeCompare(b));
  const seg = obj(manifest["segmenting"]);
  const tracks = arr(manifest["tracks"]);
  const agl = arr(manifest["agl_numbers"]);
  const files = arr(manifest["files"]);
  const inferred = Array.isArray(manifest["inferred"]) ? (manifest["inferred"] as unknown[]).map(str) : [];
  return (
    <div className="mt-2 flex flex-col gap-3" data-testid="pack-manifest">
      <Facts
        items={[
          { labelKey: "authority.pack.purpose", value: purpose },
          { labelKey: "authority.pack.case_ref", value: caseRef ?? "—" },
          { labelKey: "authority.manifest.redaction", value: str(manifest["redaction"]) },
          { labelKey: "authority.manifest.segmenting", value: t("authority.manifest.segmenting_value", { gap: str(seg["max_gap_s"]), policy: str(seg["policy_version"]) }) },
          { labelKey: "authority.manifest.seal", value: <span className="font-mono text-xs break-all">{str(seal["content_hash"])}</span> },
          { labelKey: "authority.pack.signed_by", value: signatureKid ?? t("authority.pack.unsigned") },
          { labelKey: "authority.manifest.created", value: fmtTimeUTC(typeof manifest["created_at"] === "string" ? manifest["created_at"] : null, lang, { seconds: true }) },
        ]}
      />
      <Table>
        <TableCaption>{t("authority.manifest.sections")}</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>{t("authority.manifest.section")}</TableHead>
            <TableHead>{t("authority.manifest.state")}</TableHead>
            <TableHead>{t("authority.manifest.basis")}</TableHead>
            <TableHead>{t("authority.manifest.count")}</TableHead>
            <TableHead>{t("authority.manifest.reason")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sections.map(([name, raw]) => {
            const s = obj(raw);
            return (
              <TableRow key={name} data-section={name} data-state={str(s["state"])}>
                <TableCell className="font-mono">{name}</TableCell>
                <TableCell>{str(s["state"])}</TableCell>
                <TableCell>{str(s["basis"])}</TableCell>
                <TableCell>{str(s["count"])}</TableCell>
                <TableCell>{typeof s["reason"] === "string" ? s["reason"] : ""}</TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      {tracks.length > 0 && (
        <Table>
          <TableCaption>{t("authority.manifest.tracks")}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>{t("authority.manifest.track")}</TableHead>
              <TableHead>{t("authority.manifest.samples")}</TableHead>
              <TableHead>{t("authority.manifest.segments")}</TableHead>
              <TableHead>{t("authority.manifest.holes")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tracks.map((tr) => (
              <TableRow key={str(tr["track_id"])}>
                <TableCell className="font-mono text-xs">{str(tr["track_id"])}</TableCell>
                <TableCell>{str(tr["samples"])}</TableCell>
                <TableCell>{str(tr["segments"])}</TableCell>
                <TableCell>{str(tr["holes"])}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {agl.length > 0 && (
        <ul className="m-0 ps-5 text-sm" data-testid="manifest-agl">
          {agl.map((a, i) => {
            const ts = obj(a["terrain_source"]);
            return (
              <li key={i}>
                {t("authority.manifest.agl_value", {
                  name: str(a["name"]),
                  value: fmtAltitude(typeof a["value_m"] === "number" ? a["value_m"] : null, "AGL", lang),
                  state: str(a["state"]),
                  dataset: str(ts["dataset"]),
                  spacing: str(ts["spacing_m"]),
                })}{" "}
                {typeof ts["attribution"] === "string" && <span className="text-[var(--us-text-muted)]">{ts["attribution"]}</span>}
              </li>
            );
          })}
        </ul>
      )}
      {inferred.length > 0 && (
        <div>
          <p className="m-0 text-sm font-semibold">{t("authority.manifest.inferred")}</p>
          <ul className="m-0 ps-5 text-sm">
            {inferred.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        </div>
      )}
      {files.length > 0 && (
        <Table>
          <TableCaption>{t("authority.manifest.files")}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>{t("authority.manifest.path")}</TableHead>
              <TableHead>{t("authority.manifest.sha256")}</TableHead>
              <TableHead>{t("authority.manifest.bytes")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {files.map((f) => (
              <TableRow key={str(f["path"])}>
                <TableCell className="font-mono text-xs">{str(f["path"])}</TableCell>
                <TableCell className="font-mono text-xs break-all">{str(f["sha256"])}</TableCell>
                <TableCell>{str(f["bytes"])}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

export function Manifest({ incidentId, packId }: { incidentId: string; packId: string }) {
  const { state } = useLoad(`pack:${incidentId}:${packId}`, async (c) =>
    must(await c.GET("/v1/incidents/{incident_id}/evidence-packs/{pack_id}", { params: { path: { incident_id: incidentId, pack_id: packId } } })),
  );
  if (state.kind !== "loaded") return <LoadNotice state={state} />;
  const p = state.data;
  return <ManifestView manifest={p.manifest} seal={p.seal_statement} signatureKid={p.signature_kid ?? null} purpose={p.purpose} caseRef={p.case_ref ?? null} />;
}
