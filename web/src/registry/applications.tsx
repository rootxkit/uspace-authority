"use client";

// The registration applications of the portal (WP-20;
// docs/runbooks/registry-portal.md), registrars only. Behind the
// REGISTRY_APPLICATIONS flag: off, api answers 404 to every application
// operation, and the queue says the portal is off instead of showing an
// empty queue. A row lists no personal data; its content opens behind a
// purpose. Review, approval and refusal are api's operations, each
// confirmed with its effect.
import { useMemo, useState } from "react";
import { useT, fmtRegistrationNumber } from "@rootxkit/uspace-ui/i18n";
import { DataTable, columnsFor } from "@rootxkit/uspace-ui/table";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { Button, EmptyState, Input, Label } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { must, useConsole, useLoad } from "../authoring/api";
import { PersonalData } from "../authoring/PersonalData";
import { Act, Can, Facts, PageHeader, ProblemNotice, Section, UTC } from "../authoring/ui";
import { RegistryTabs } from "./common";
import { NotYourRole } from "./operators";

type Application = components["schemas"]["RegistryApplication"];
type AppState = components["schemas"]["RegistryApplicationState"];

export const APPLICATION_STATES: readonly AppState[] = ["submitted", "under_review", "unverified", "approved", "refused"];

export function ApplicationsPage() {
  return (
    <div className="flex flex-col" data-testid="applications-page">
      <PageHeader titleKey="authority.registry.applications.title" />
      <RegistryTabs />
      <Can roles={["registrar"]} fallback={<div className="px-4 py-3"><NotYourRole /></div>}>
        <Queue />
      </Can>
    </div>
  );
}

function Queue() {
  const t = useT();
  const [state, setState] = useState<AppState>("submitted");
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [selected, setSelected] = useState<Application | null>(null);
  const cursor = cursors[cursors.length - 1];
  const { state: load, reload } = useLoad(`applications|${state}|${cursor ?? ""}`, async (c) =>
    must(await c.GET("/v1/registry/applications", { params: { query: { state, ...(cursor === undefined ? {} : { cursor }) } } })),
  );
  const c = columnsFor<Application>();
  const cols = useMemo(
    () => [
      c.text("application_id", { headerKey: "authority.registry.applications.id", mono: true }),
      c.enum("operator_type", "authority.registry.operator_type", { headerKey: "authority.registry.f.operator_type" }),
      c.enum("state", "authority.registry.applications.state", { headerKey: "authority.registry.applications.state_h" }),
      c.utc("submitted_at", { headerKey: "authority.registry.applications.submitted_at" }),
      c.utc("verified_at", { headerKey: "authority.registry.applications.verified_at" }),
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t],
  );
  return (
    <div className="flex flex-col gap-3 px-4 py-3">
      <div className="flex flex-col gap-1 self-start">
        <Label htmlFor="app-state">{t("authority.registry.applications.state_h")}</Label>
        <select
          id="app-state"
          className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1 text-sm"
          value={state}
          onChange={(e) => {
            setState(e.target.value as AppState);
            setCursors([undefined]);
            setSelected(null);
          }}
        >
          {APPLICATION_STATES.map((s) => (
            <option key={s} value={s}>
              {t(`authority.registry.applications.state.${s}`)}
            </option>
          ))}
        </select>
      </div>
      {load.kind === "refused" && load.error.status === 404 ? (
        <p role="status" className="m-0 text-sm" data-testid="applications-off">
          {t("authority.registry.applications.off")}
        </p>
      ) : load.kind === "refused" ? (
        <ProblemNotice error={load.error} />
      ) : load.kind === "failed" ? (
        <ProblemNotice error="failed" />
      ) : load.kind === "loading" ? (
        <p className="m-0 text-sm">{t("authority.act.loading")}</p>
      ) : (
        <>
          <DataTable<Application>
            columns={cols}
            rows={load.data.applications}
            getRowId={(r) => r.application_id}
            caption={t("authority.registry.applications.title")}
            captionHidden
            toolbar={false}
            selectedId={selected?.application_id ?? null}
            onSelect={(r: Application) => setSelected(r)}
            empty={<EmptyState title={t("authority.registry.applications.empty", { state: t(`authority.registry.applications.state.${state}`) })} />}
          />
          <div className="flex gap-2">
            <Button type="button" size="sm" variant="outline" disabled={cursors.length === 1} onClick={() => setCursors((x) => x.slice(0, -1))}>
              {t("ui.previous_page")}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={load.data.next_cursor === undefined}
              onClick={() => setCursors((x) => [...x, load.data.next_cursor])}
            >
              {t("ui.next_page")}
            </Button>
          </div>
        </>
      )}
      {selected !== null && (
        <ApplicationPanel
          key={selected.application_id}
          app={selected}
          onChanged={(a) => {
            setSelected(a);
            reload();
          }}
        />
      )}
    </div>
  );
}

function ApplicationPanel({ app, onChanged }: { app: Application; onChanged(a: Application): void }) {
  const t = useT();
  const client = useConsole();
  const [validUntil, setValidUntil] = useState("");
  const id = app.application_id;
  const until = validUntil === "" ? null : inputToUtc(validUntil);
  return (
    <Section titleKey="authority.registry.applications.one" vars={{ id }} testId="application">
      <Facts
        items={[
          ["authority.registry.applications.state_h", t(`authority.registry.applications.state.${app.state}`)],
          ["authority.registry.applications.submitted_at", <UTC key="s" iso={app.submitted_at} />],
          ["authority.registry.applications.verified_at", <UTC key="v" iso={app.verified_at} />],
          ["authority.registry.applications.review_started_at", <UTC key="r" iso={app.review_started_at} />],
          ["authority.registry.applications.registrar", app.registrar_id],
          ["authority.registry.applications.decided_at", <UTC key="d" iso={app.decided_at} />],
          ["authority.registry.applications.refusal_reason", app.refusal_reason],
          ["authority.registry.f.registration_number", app.registration_number === undefined ? null : fmtRegistrationNumber(app.registration_number)],
          ["authority.registry.f.valid_until", <UTC key="u" iso={app.valid_until} />],
          ["authority.registry.applications.lang", t(`authority.locale.${app.lang}`)],
        ]}
      />
      <PersonalData
        roles={["registrar"]}
        testId="application-pii"
        read={async (purpose) => must(await client.GET("/v1/registry/applications/{application_id}/personal-data", { params: { path: { application_id: id }, query: { purpose } } }))}
        rows={(p) => [
          ["authority.registry.f.operator_type", t(`authority.registry.operator_type.${p.operator_type}`)],
          ["authority.registry.f.full_name", p.full_name],
          ["authority.registry.f.legal_name", p.legal_name],
          ["authority.registry.f.date_of_birth", p.date_of_birth],
          ["authority.registry.f.legal_identification_number", p.legal_identification_number],
          ["authority.registry.f.postal_address", p.postal_address],
          ["authority.registry.f.contact_email", p.contact_email],
          ["authority.registry.f.contact_phone", p.contact_phone],
          ["authority.registry.f.insurance_policy_number", p.insurance_policy_number],
          ["authority.registry.f.competency_confirmation", p.competency_confirmation === undefined ? null : t(p.competency_confirmation ? "common.yes" : "common.no")],
          ["authority.registry.f.authorisations", p.authorisations === undefined || p.authorisations.length === 0 ? null : JSON.stringify(p.authorisations)],
        ]}
      />
      <div className="flex flex-wrap items-end gap-3">
        {app.state === "submitted" && (
          <Act
            labelKey="authority.registry.applications.review"
            titleKey="authority.registry.applications.review_title"
            bodyKey="authority.registry.applications.review_body"
            vars={{ id }}
            run={async () => must(await client.POST("/v1/registry/applications/{application_id}/review", { params: { path: { application_id: id } } }))}
            onDone={onChanged}
            testId="application-review"
          />
        )}
        {(app.state === "submitted" || app.state === "under_review") && (
          <>
            <div className="flex flex-col gap-1">
              <Label htmlFor="app-valid-until">{t("authority.registry.applications.valid_until")}</Label>
              <Input id="app-valid-until" type="datetime-local" value={validUntil} onChange={(e) => setValidUntil(e.target.value)} />
            </div>
            <Act
              labelKey="authority.registry.applications.approve"
              titleKey="authority.registry.applications.approve_title"
              bodyKey={until === null ? "authority.registry.applications.approve_body_default" : "authority.registry.applications.approve_body"}
              vars={{ id, until: until ?? "" }}
              run={async () =>
                must(
                  await client.POST("/v1/registry/applications/{application_id}/approve", {
                    params: { path: { application_id: id } },
                    body: until === null ? {} : { valid_until: until },
                  }),
                )
              }
              onDone={onChanged}
              testId="application-approve"
            />
            <Act
              labelKey="authority.registry.applications.refuse"
              titleKey="authority.registry.applications.refuse_title"
              bodyKey="authority.registry.applications.refuse_body"
              vars={{ id }}
              reason={{ minLength: 1 }}
              destructive
              run={async (reason) =>
                must(await client.POST("/v1/registry/applications/{application_id}/refuse", { params: { path: { application_id: id } }, body: { reason: (reason ?? "").slice(0, 500) } }))
              }
              onDone={onChanged}
              testId="application-refuse"
            />
          </>
        )}
      </div>
    </Section>
  );
}
