"use client";

// The registry import (WP-20; docs/runbooks/registry-import.md): one
// export file of one kind, CSV or a JSON array, checked by api's rules
// file. The page runs the dry run first and shows its report by record
// and field; the import itself is offered only for the file the dry run
// read without a problem (the same SHA-256 api reported), and confirms
// its counts before it writes. api decides everything; the page reads
// no value of the file.
import { useState } from "react";
import type { ApiError } from "@rootxkit/uspace-ui/api";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { FieldErrors } from "@rootxkit/uspace-ui/form";
import { Button, Label } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import type { ConsoleClient } from "../api/client";
import { must, outcomeOf, useConsole } from "../authoring/api";
import { Act, Can, Facts, PageHeader, ProblemNotice, Section } from "../authoring/ui";
import { RegistryTabs } from "./common";
import { NotYourRole } from "./operators";

type Report = components["schemas"]["RegistryImportReport"];
type Kind = components["schemas"]["RegistryImportKind"];

export const IMPORT_KINDS: readonly Kind[] = ["operators", "uas"];

/** The body's media type from the file: JSON by its name or type, CSV otherwise (api reads both). */
export function importMediaType(file: { name: string; type: string }): "application/json" | "text/csv" {
  return file.type === "application/json" || /\.json$/i.test(file.name) ? "application/json" : "text/csv";
}

async function runImport(client: ConsoleClient, kind: Kind, dryRun: boolean, text: string, media: string): Promise<Report> {
  return must(
    await client.POST("/v1/registry/import", {
      params: { query: { kind, dry_run: dryRun } },
      // The file's bytes as read; api parses them under its rules file.
      body: text as never,
      bodySerializer: (b: unknown) => b as string,
      headers: { "Content-Type": media },
    }),
  );
}

export function RegistryImport() {
  const t = useT();
  const client = useConsole();
  const [kind, setKind] = useState<Kind>("operators");
  const [file, setFile] = useState<{ name: string; text: string; media: string } | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [applied, setApplied] = useState<Report | null>(null);
  const [error, setError] = useState<ApiError | "failed" | null>(null);
  const [busy, setBusy] = useState(false);
  const clean = report !== null && report.dry_run && report.problems.length === 0;
  return (
    <div className="flex flex-col" data-testid="registry-import">
      <PageHeader titleKey="authority.registry.import.title" />
      <RegistryTabs />
      <Can roles={["registrar"]} fallback={<div className="px-4 py-3"><NotYourRole /></div>}>
        <Section titleKey="authority.registry.import.file">
          <p className="m-0 text-sm">{t("authority.registry.import.intro")}</p>
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (file === null) return;
              setBusy(true);
              setError(null);
              setReport(null);
              setApplied(null);
              runImport(client, kind, true, file.text, file.media)
                .then(setReport)
                .catch((err: unknown) => {
                  const o = outcomeOf(err);
                  setError(o.kind === "refused" ? o.error : "failed");
                })
                .finally(() => setBusy(false));
            }}
          >
            <div className="flex flex-col gap-1">
              <Label htmlFor="import-kind">{t("authority.registry.import.kind")}</Label>
              <select
                id="import-kind"
                className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1 text-sm"
                value={kind}
                onChange={(e) => {
                  setKind(e.target.value as Kind);
                  setReport(null);
                }}
                data-testid="import-kind"
              >
                {IMPORT_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {t(`authority.registry.import.kind_${k}`)}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="import-file">{t("authority.registry.import.choose")}</Label>
              <input
                id="import-file"
                type="file"
                accept=".csv,.json,text/csv,application/json"
                className="text-sm"
                data-testid="import-file"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  setReport(null);
                  setApplied(null);
                  if (f === undefined) return setFile(null);
                  void f.text().then((text) => setFile({ name: f.name, text, media: importMediaType(f) }));
                }}
              />
            </div>
            <Button type="submit" size="sm" disabled={file === null || busy} data-testid="import-dry-run">
              {t("authority.registry.import.dry_run")}
            </Button>
          </form>
          {error !== null && <ProblemNotice error={error} testId="import-problem" />}
        </Section>
        {report !== null && <ReportView report={report} testId="import-report" />}
        {clean && file !== null && (
          <Section titleKey="authority.registry.import.apply_title">
            <Act
              labelKey="authority.registry.import.apply"
              titleKey="authority.registry.import.apply_confirm_title"
              bodyKey="authority.registry.import.apply_confirm_body"
              vars={{ created: report.created, updated: report.updated, unchanged: report.unchanged, kind: t(`authority.registry.import.kind_${kind}`), sha: report.content_sha256.slice(0, 12) }}
              run={() => runImport(client, kind, false, file.text, file.media)}
              onDone={(r) => {
                setApplied(r);
                setReport(null);
              }}
              testId="import-apply"
            />
          </Section>
        )}
        {applied !== null && <ReportView report={applied} testId="import-applied" />}
      </Can>
    </div>
  );
}

function ReportView({ report, testId }: { report: Report; testId: string }) {
  const t = useT();
  return (
    <Section titleKey={report.dry_run ? "authority.registry.import.report_dry" : "authority.registry.import.report_applied"} testId={testId}>
      <Facts
        items={[
          ["authority.registry.import.records", String(report.records)],
          ["authority.registry.import.created", String(report.created)],
          ["authority.registry.import.updated", String(report.updated)],
          ["authority.registry.import.unchanged", String(report.unchanged)],
          ["authority.registry.import.applied", t(report.applied ? "common.yes" : "common.no")],
          ["authority.registry.import.registry_version", report.registry_version === undefined ? null : String(report.registry_version)],
          ["authority.registry.import.rules_version", report.rules_version],
          ["authority.registry.import.sha", <span key="s" className="font-mono">{report.content_sha256}</span>],
        ]}
      />
      {report.problems.length > 0 ? (
        <div data-testid={`${testId}-problems`}>
          <p className="m-0 text-sm font-semibold">{t("authority.registry.import.problems", { n: report.problems.length })}</p>
          <FieldErrors errors={report.problems} truncated={report.problems_truncated === true} />
          <p className="m-0 text-xs">{t("authority.registry.import.nothing_written")}</p>
        </div>
      ) : (
        <p className="m-0 text-sm" data-testid={`${testId}-clean`}>
          {t("authority.registry.import.no_problems")}
        </p>
      )}
      {report.outcomes.length > 0 && (
        <table className="w-full text-sm" data-testid={`${testId}-outcomes`}>
          <caption className="text-start font-semibold">{t("authority.registry.import.outcomes")}</caption>
          <thead>
            <tr>
              <th className="text-start">{t("authority.registry.import.record")}</th>
              <th className="text-start">{t("authority.registry.import.source_id")}</th>
              <th className="text-start">{t("authority.registry.import.action")}</th>
              <th className="text-start">{t("authority.registry.import.fields")}</th>
              <th className="text-start">{t("authority.registry.f.status")}</th>
            </tr>
          </thead>
          <tbody>
            {report.outcomes.map((o) => (
              <tr key={o.record} data-record={o.record}>
                <td>{o.record}</td>
                <td className="font-mono">{o.source_id}</td>
                <td>{t(`authority.registry.import.action_${o.action}`)}</td>
                <td>{(o.fields ?? []).join(", ")}</td>
                <td>{t(`authority.registry.status.${o.status}`)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {report.outcomes_truncated === true && <p className="m-0 text-xs">{t("authority.registry.import.outcomes_truncated")}</p>}
    </Section>
  );
}
