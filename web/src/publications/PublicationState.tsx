"use client";

// The F1 outbox as api reports it (WP-6; GET /v1/publications;
// docs/runbooks/cisp-publication.md): each publication of a dataset with
// its state, the CISP's answer, and while it is pending or sent the
// "not yet published for N s" age api computes (age_s). Without
// CISP_BASE_URL nothing is sent, and the panel says so first. While a
// row is in flight the panel reads again every PUBLICATION_REFRESH_MS;
// it reads nothing more often and stops when none is.
import { useEffect } from "react";
import { fmtAge, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Badge } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { must, useLoad } from "../authoring/api";
import { Loaded, UTC } from "../authoring/ui";

type Row = components["schemas"]["PublicationOutboxRow"];
type Status = components["schemas"]["PublicationStatus"];
export type PublicationDataset = Row["dataset"];

/** How often an in-flight publication is read again. A display period, not a threshold. */
export const PUBLICATION_REFRESH_MS = 5000;
/** The rows shown: the newest of the dataset. A display bound. */
export const PUBLICATION_ROWS = 5;

const IN_FLIGHT: readonly Row["state"][] = ["pending", "sent"];

export function PublicationState({ dataset, round = 0 }: { dataset: PublicationDataset; round?: number }) {
  const t = useT();
  const { lang } = useLang();
  const { state, reload } = useLoad(`publications|${dataset}|${round}`, async (c) =>
    must(await c.GET("/v1/publications", { params: { query: { dataset, limit: PUBLICATION_ROWS } } })),
  );
  const inFlight = state.kind === "loaded" && state.data.publications.some((r) => IN_FLIGHT.includes(r.state));
  useEffect(() => {
    if (!inFlight) return;
    const id = setTimeout(reload, PUBLICATION_REFRESH_MS);
    return () => clearTimeout(id);
  }, [inFlight, reload, state]);
  return (
    <section className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-3" aria-label={t("authority.pub.title")} data-testid={`publications-${dataset}`}>
      <h2 className="m-0 text-base font-semibold">{t("authority.pub.title")}</h2>
      <Loaded state={state} testId={`publications-${dataset}`}>
        {(s: Status) => (
          <>
            {!s.cisp_configured && (
              <p role="alert" className="m-0 text-sm text-[var(--us-danger)]" data-testid="cisp-not-configured">
                {t("authority.pub.cisp_not_configured")}
              </p>
            )}
            {s.publications.length === 0 ? (
              <p className="m-0 text-sm" data-testid="publications-none">
                {t("authority.pub.none", { dataset: t(`authority.pub.dataset.${dataset}`) })}
              </p>
            ) : (
              <ul className="m-0 flex list-none flex-col gap-2 p-0">
                {s.publications.map((r) => (
                  <li key={r.id} className="flex flex-col gap-1 text-sm" data-testid="publication" data-state={r.state} data-version={r.version}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-semibold">{t("authority.pub.version", { version: r.version, n: r.feature_count })}</span>
                      <Badge variant={r.state === "acknowledged" ? "secondary" : r.state === "failed" || r.state === "conflict" ? "destructive" : "outline"}>
                        {t(`authority.pub.state.${r.state}`)}
                      </Badge>
                      {r.age_s !== null && IN_FLIGHT.includes(r.state) && (
                        <span data-testid="publication-age">{t("authority.pub.not_yet", { age: fmtAge(r.age_s, lang) })}</span>
                      )}
                    </div>
                    <span className="text-xs text-[var(--us-text-muted)]">
                      {t("authority.pub.attempts", { n: r.attempts })}
                      {r.last_status !== null && r.last_status !== undefined && ` · ${t("authority.pub.last_status", { status: r.last_status })}`}
                      {r.cisp_version !== null && r.cisp_version !== undefined && ` · ${t("authority.pub.cisp_version", { version: r.cisp_version })}`}
                      {r.conflict_version !== null && r.conflict_version !== undefined && ` · ${t("authority.pub.conflict_version", { version: r.conflict_version })}`}
                    </span>
                    {r.last_error !== null && r.last_error !== undefined && r.last_error !== "" && <span className="text-xs">{t("authority.pub.last_error", { error: r.last_error })}</span>}
                    <span className="text-xs">
                      {t("authority.pub.created_by", { by: r.created_by })} <UTC iso={r.created_at} />
                      {r.acknowledged_at !== null && r.acknowledged_at !== undefined && (
                        <>
                          {" · "}
                          {t("authority.pub.acknowledged_at")} <UTC iso={r.acknowledged_at} />
                        </>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <p className="m-0 text-xs text-[var(--us-text-muted)]" data-testid="heartbeat">
              {s.heartbeat.enabled
                ? t("authority.pub.heartbeat", { failures: s.heartbeat.consecutive_failures })
                : t("authority.pub.heartbeat_off")}
            </p>
          </>
        )}
      </Loaded>
    </section>
  );
}
