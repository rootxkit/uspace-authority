"use client";

// The ED-318 and ED-269 import (WP-5; docs/runbooks/zones.md "Import"):
// the file's bytes as they are, with the period of validity when the
// file has none. api detects the format, imports all or nothing, and
// refuses with every problem by JSON path (features[3].restriction),
// which the page lists as api wrote them. A file larger than api reads
// is refused here before it is sent.
import { useState } from "react";
import Link from "next/link";
import { fmtNum, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { Button, Input, Label } from "@rootxkit/uspace-ui/ui";
import type { ApiError } from "@rootxkit/uspace-ui/api";
import type { components } from "../api/types";
import { must, outcomeOf, useConsole } from "../authoring/api";
import { Can, PageHeader, ProblemNotice, Section } from "../authoring/ui";
import { zonePath } from "./editor/ZoneEditor";
import { listPath, ROLES } from "./pages";

type ImportResult = components["schemas"]["ZoneImportResult"];

/** api's largest import, bytes (zonesvc MaxDocumentBytes: uspace-core ed269.DefaultLimits.MaxBytes, 4 MiB). */
export const ZONE_IMPORT_MAX_BYTES = 4 * 1024 * 1024;

export function ZoneImport() {
  const t = useT();
  const { lang } = useLang();
  const client = useConsole();
  const [file, setFile] = useState<File | null>(null);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | "failed" | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const tooBig = file !== null && file.size > ZONE_IMPORT_MAX_BYTES;
  return (
    <div className="flex flex-col" data-testid="zone-import-page">
      <PageHeader titleKey="authority.zone.import" back={{ href: listPath(lang, "zones"), labelKey: "authority.zones.title" }} />
      <Can roles={ROLES.zones.author} fallback={<p className="m-0 px-4 py-3 text-sm">{t("authority.act.not_your_role")}</p>}>
        <Section titleKey="authority.zone.import_file">
          <p className="m-0 text-sm">{t("authority.zone.import_intro")}</p>
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (file === null || tooBig) return;
              const vf = from === "" ? null : inputToUtc(from);
              const vt = to === "" ? null : inputToUtc(to);
              setBusy(true);
              setError(null);
              setResult(null);
              void file
                .arrayBuffer()
                .then(async (bytes) =>
                  must(
                    await client.POST("/v1/zones/import", {
                      params: { query: { ...(vf === null ? {} : { valid_from: vf }), ...(vt === null ? {} : { valid_to: vt }) } },
                      // The file's bytes, unread by the page (api detects ED-318 or ED-269).
                      body: bytes as never,
                      bodySerializer: (b: unknown) => b as ArrayBuffer,
                      headers: { "Content-Type": "application/octet-stream" },
                    }),
                  ),
                )
                .then(setResult)
                .catch((err: unknown) => {
                  const o = outcomeOf(err);
                  setError(o.kind === "refused" ? o.error : "failed");
                })
                .finally(() => setBusy(false));
            }}
          >
            <div className="flex flex-col gap-1">
              <Label htmlFor="zone-file">{t("authority.zone.import_choose")}</Label>
              <input
                id="zone-file"
                type="file"
                accept=".json,.geojson,application/json,application/geo+json"
                className="text-sm"
                data-testid="zone-file"
                onChange={(e) => {
                  setFile(e.target.files?.[0] ?? null);
                  setResult(null);
                  setError(null);
                }}
              />
              {tooBig && (
                <p role="alert" className="m-0 text-sm text-[var(--us-danger)]" data-testid="zone-file-too-big">
                  {t("authority.zone.import_too_big", { max: fmtNum(ZONE_IMPORT_MAX_BYTES, 0, undefined, lang) })}
                </p>
              )}
            </div>
            <div className="grid gap-2 md:grid-cols-2">
              <div className="flex flex-col gap-1">
                <Label htmlFor="import-from">{t("authority.zone.import_valid_from")}</Label>
                <Input id="import-from" type="datetime-local" step={1} value={from} onChange={(e) => setFrom(e.target.value)} />
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="import-to">{t("authority.zone.import_valid_to")}</Label>
                <Input id="import-to" type="datetime-local" step={1} value={to} onChange={(e) => setTo(e.target.value)} />
              </div>
            </div>
            <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("authority.zone.import_period_hint")}</p>
            <Button type="submit" size="sm" className="self-start" disabled={file === null || tooBig || busy} data-testid="zone-import-submit">
              {t("authority.zone.import_submit")}
            </Button>
          </form>
          {error !== null && (
            <div className="flex flex-col gap-1" data-testid="zone-import-refused">
              <ProblemNotice error={error} testId="zone-import-problem" />
              <p className="m-0 text-xs">{t("authority.zone.import_nothing")}</p>
            </div>
          )}
        </Section>
        {result !== null && (
          <Section titleKey="authority.zone.import_done" vars={{ n: result.created.length, format: result.format }} testId="zone-import-result">
            <ul className="m-0 ps-4 text-sm">
              {result.created.map((z) => (
                <li key={`${z.identifier}@${z.zone_version}`}>
                  <Link className="underline" href={zonePath(lang, "zones", z.identifier)}>
                    {t("authority.zone.import_created", { id: z.identifier, version: z.zone_version })}
                  </Link>
                </li>
              ))}
            </ul>
          </Section>
        )}
      </Can>
    </div>
  );
}
