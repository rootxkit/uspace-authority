"use client";

// Remote pilots (api/openapi.yaml /v1/registry/pilots*): the list by
// operator and status, the detail with the competencies, the name and
// the national id's last four behind a purpose, the form to register and
// to edit, the competency record and the status transition.
import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { z } from "zod";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Form, TextField, UTCDateTimeField, shapes } from "@rootxkit/uspace-ui/form";
import { columnsFor, tableColumn } from "@rootxkit/uspace-ui/table";
import { Input, Label } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { must, useConsole, useLoad } from "../authoring/api";
import { compact } from "../authoring/fields";
import { PersonalData } from "../authoring/PersonalData";
import { Can, Facts, Loaded, PageHeader, Section } from "../authoring/ui";
import { Filters, RegistryList, RegistryTabs, StatusBadge, StatusChange, registryPath } from "./common";
import { NotYourRole, StatusFilter } from "./operators";
import { byAt } from "./words";

export type Pilot = components["schemas"]["RegistryPilot"];
type PilotInput = components["schemas"]["RegistryPilotInput"];
type PilotPatch = components["schemas"]["RegistryPilotPatch"];

/** api's PilotCompetencyInput.competency: A1_A3, A2, STS_01, STS_02 or national_<code>. */
export const COMPETENCY = /^(A1_A3|A2|STS_01|STS_02|national_[A-Za-z0-9_]{1,32})$/;

export function PilotTable({ operatorId, status = "" }: { operatorId?: string; status?: string }) {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const c = columnsFor<Pilot>();
  const cols = useMemo(
    () => [
      c.text("id", { headerKey: "authority.registry.f.pilot_id", mono: true }),
      c.text("operator_id", { headerKey: "authority.registry.f.operator", mono: true }),
      tableColumn<Pilot, Pilot["competencies"]>({
        id: "competencies",
        accessorKey: "competencies",
        header: () => t("authority.registry.f.competencies"),
        cell: (ctx) => ctx.getValue().map((x) => x.competency).join(", "),
      }),
      tableColumn<Pilot, string>({ id: "status", accessorKey: "status", header: () => t("authority.registry.f.status"), cell: (ctx) => <StatusBadge status={ctx.getValue()} /> }),
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t],
  );
  const key = `pilots|${operatorId ?? ""}|${status}`;
  return (
    <RegistryList<Pilot>
      key={key}
      queryKey={key}
      read={async (cl, after) => {
        const d = must(
          await cl.GET("/v1/registry/pilots", {
            params: {
              query: {
                ...(operatorId === undefined || operatorId === "" ? {} : { operator_id: operatorId }),
                ...(status === "" ? {} : { status: status as Pilot["status"] }),
                ...(after === undefined ? {} : { after }),
              },
            },
          }),
        );
        return { rows: d.pilots, next: d.next_after };
      }}
      columns={cols}
      getRowId={(r) => r.id}
      captionKey="authority.registry.pilots.title"
      emptyKey="authority.registry.pilots.empty"
      onSelect={(r) => router.push(registryPath(lang, `pilots/${encodeURIComponent(r.id)}`))}
      testId="pilots"
    />
  );
}

export function PilotsPage() {
  const t = useT();
  const { lang } = useLang();
  const [operator, setOperator] = useState("");
  const [status, setStatus] = useState("");
  const [applied, setApplied] = useState({ operator: "", status: "" });
  return (
    <div className="flex flex-col" data-testid="pilots-page">
      <PageHeader titleKey="authority.registry.pilots.title">
        <Can roles={["registrar"]}>
          <Link href={registryPath(lang, "pilots/new")} className="text-sm font-semibold underline" data-testid="pilot-new">
            {t("authority.registry.pilots.new")}
          </Link>
        </Can>
      </PageHeader>
      <RegistryTabs />
      <div className="flex flex-col gap-3 px-4 py-3">
        <Filters labelKey="authority.registry.filters" onApply={() => setApplied({ operator: operator.trim(), status })}>
          <div className="flex flex-col gap-1">
            <Label htmlFor="pilot-operator">{t("authority.registry.search_operator")}</Label>
            <Input id="pilot-operator" value={operator} maxLength={32} onChange={(e) => setOperator(e.target.value)} />
          </div>
          <StatusFilter value={status} onChange={setStatus} />
        </Filters>
        <PilotTable operatorId={applied.operator} status={applied.status} />
      </div>
    </div>
  );
}

export function PilotDetail({ id }: { id: string }) {
  const t = useT();
  const { lang } = useLang();
  const client = useConsole();
  const [editing, setEditing] = useState(false);
  const { state, reload } = useLoad(`pilot|${id}`, async (c) => must(await c.GET("/v1/registry/pilots/{pilot_id}", { params: { path: { pilot_id: id } } })));
  return (
    <div className="flex flex-col" data-testid="pilot-detail">
      <PageHeader titleKey="authority.registry.pilots.detail" back={{ href: registryPath(lang, "pilots"), labelKey: "authority.registry.pilots.back" }} />
      <RegistryTabs />
      <Loaded state={state} testId="pilot">
        {(p) => (
          <>
            <Section titleKey="authority.registry.facts">
              <Facts
                items={[
                  ["authority.registry.f.pilot_id", <span key="i" className="font-mono">{p.id}</span>],
                  [
                    "authority.registry.f.operator",
                    p.operator_id === undefined ? null : (
                      <Link key="o" className="underline" href={registryPath(lang, `operators/${encodeURIComponent(p.operator_id)}`)}>
                        {p.operator_id}
                      </Link>
                    ),
                  ],
                  ["authority.registry.f.status", <StatusBadge key="s" status={p.status} />],
                  ["authority.registry.f.status_reason", p.status_reason],
                  ["authority.registry.f.registry_version", String(p.registry_version)],
                  ["authority.registry.f.updated", byAt(t, lang, p.updated_by, p.updated_at)],
                ]}
              />
            </Section>
            <Section titleKey="authority.registry.f.competencies">
              {p.competencies.length === 0 ? (
                <p className="m-0 text-sm">{t("authority.registry.competencies_none")}</p>
              ) : (
                <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm" data-testid="competencies">
                  {p.competencies.map((c) => (
                    <li key={`${c.competency}|${c.certificate_ref}`}>
                      {t("authority.registry.competency_line", { competency: c.competency, ref: c.certificate_ref, until: fmtTimeUTC(c.valid_until, lang), by: c.recorded_by })}
                    </li>
                  ))}
                </ul>
              )}
              <Can roles={["registrar"]}>
                <CompetencyForm pilotId={p.id} onSaved={reload} />
              </Can>
            </Section>
            <Section titleKey="authority.registry.status_title">
              <StatusChange
                subject={p.id}
                current={p.status}
                run={async (status, reason) => must(await client.POST("/v1/registry/pilots/{pilot_id}/status", { params: { path: { pilot_id: id } }, body: { status, reason } }))}
                onDone={reload}
              />
            </Section>
            <div className="px-4 py-3">
              <PersonalData
                roles={["registrar", "inspector"]}
                testId="pilot-pii"
                read={async (purpose) => must(await client.GET("/v1/registry/pilots/{pilot_id}/personal-data", { params: { path: { pilot_id: id }, query: { purpose } } }))}
                rows={(d) => [
                  ["authority.registry.f.name", d.name],
                  ["authority.registry.f.person_ref_last4", d.person_ref_last4],
                ]}
              />
            </div>
            <Can roles={["registrar"]}>
              <Section titleKey="authority.registry.edit">
                {editing ? (
                  <PilotForm
                    mode={{ kind: "edit", pilot: p }}
                    onSaved={() => {
                      setEditing(false);
                      reload();
                    }}
                  />
                ) : (
                  <button type="button" className="self-start text-sm underline" onClick={() => setEditing(true)} data-testid="pilot-edit">
                    {t("authority.registry.edit_open")}
                  </button>
                )}
              </Section>
            </Can>
          </>
        )}
      </Loaded>
    </div>
  );
}

const competencySchema = z.object({
  competency: z.string().trim().max(41).regex(COMPETENCY, { message: "authority.registry.competency_shape" }),
  certificate_ref: z.string().trim().min(1).max(64),
  valid_until: shapes.utcTime(),
});

function CompetencyForm({ pilotId, onSaved }: { pilotId: string; onSaved(): void }) {
  const client = useConsole();
  return (
    <Form
      schema={competencySchema}
      defaults={{ competency: "", certificate_ref: "", valid_until: "" }}
      submitLabelKey="authority.registry.competency_record"
      onSubmit={async (v) => {
        must(await client.POST("/v1/registry/pilots/{pilot_id}/competencies", { params: { path: { pilot_id: pilotId } }, body: v }));
        onSaved();
      }}
    >
      <div className="grid gap-3 md:grid-cols-3" data-testid="competency-form">
        <TextField name="competency" labelKey="authority.registry.f.competency" hintKey="authority.registry.h.competency" required />
        <TextField name="certificate_ref" labelKey="authority.registry.f.certificate_ref" required />
        <UTCDateTimeField name="valid_until" labelKey="authority.registry.f.valid_until" required />
      </div>
    </Form>
  );
}

type PilotMode = { kind: "create" } | { kind: "edit"; pilot: Pilot };

function pilotSchema(create: boolean) {
  return z.object({
    person_ref: create ? z.string().trim().min(4).max(64) : z.string().optional(),
    name: create ? z.string().trim().min(1).max(200) : z.string().max(200).optional(),
    operator_id: z.string().trim().max(32).optional(),
  });
}

export function PilotForm({ mode, onSaved }: { mode: PilotMode; onSaved(p: Pilot): void }) {
  const client = useConsole();
  const create = mode.kind === "create";
  const schema = useMemo(() => pilotSchema(create), [create]);
  return (
    <Form
      schema={schema}
      defaults={{ person_ref: "", name: "", operator_id: mode.kind === "edit" ? (mode.pilot.operator_id ?? "") : "" }}
      submitLabelKey={create ? "authority.registry.pilots.register" : "authority.registry.save"}
      onSubmit={async (v) => {
        if (mode.kind === "create") {
          onSaved(must(await client.POST("/v1/registry/pilots", { body: compact(v) as PilotInput })));
          return;
        }
        // An emptied operator detaches the pilot (RegistryPilotPatch.operator_id "").
        const body: PilotPatch = { ...compact({ name: v.name }) };
        if ((v.operator_id ?? "") !== (mode.pilot.operator_id ?? "")) body.operator_id = v.operator_id ?? "";
        onSaved(must(await client.PATCH("/v1/registry/pilots/{pilot_id}", { params: { path: { pilot_id: mode.pilot.id } }, body })));
      }}
    >
      <div className="grid gap-3 md:grid-cols-3" data-testid="pilot-form">
        {create && <TextField name="person_ref" labelKey="authority.registry.f.person_ref" hintKey="authority.registry.h.person_ref" autoComplete="off" required />}
        <TextField name="name" labelKey="authority.registry.f.name" required={create} hintKey={create ? undefined : "authority.registry.h.pii_not_shown"} />
        <TextField name="operator_id" labelKey="authority.registry.f.operator" hintKey={create ? "authority.registry.h.operator_id" : "authority.registry.h.detach"} />
      </div>
    </Form>
  );
}

export function PilotNew() {
  const { lang } = useLang();
  const router = useRouter();
  return (
    <div className="flex flex-col" data-testid="pilot-new-page">
      <PageHeader titleKey="authority.registry.pilots.new" back={{ href: registryPath(lang, "pilots"), labelKey: "authority.registry.pilots.back" }} />
      <RegistryTabs />
      <div className="px-4 py-3">
        <Can roles={["registrar"]} fallback={<NotYourRole />}>
          <PilotForm mode={{ kind: "create" }} onSaved={(p) => router.push(registryPath(lang, `pilots/${encodeURIComponent(p.id)}`))} />
        </Can>
      </div>
    </div>
  );
}
