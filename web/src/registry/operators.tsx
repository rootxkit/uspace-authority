"use client";

// UAS operators (api/openapi.yaml /v1/registry/operators*): the list
// with the look-up by registration number, the detail without personal
// data, the personal data behind a purpose, the Art. 14(2) form to
// register and to edit, and the status transition.
import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { z } from "zod";
import { useLang, useT, fmtRegistrationNumber } from "@rootxkit/uspace-ui/i18n";
import { CheckboxField, EnumField, Form, TextField, UTCDateTimeField, shapes } from "@rootxkit/uspace-ui/form";
import { columnsFor, tableColumn } from "@rootxkit/uspace-ui/table";
import { Input, Label } from "@rootxkit/uspace-ui/ui";
import { useWatch } from "react-hook-form";
import Link from "next/link";
import type { components } from "../api/types";
import { must, useConsole, useLoad } from "../authoring/api";
import { TextareaField, compact } from "../authoring/fields";
import { PersonalData } from "../authoring/PersonalData";
import { Can, Facts, Loaded, PageHeader, Section, UTC } from "../authoring/ui";
import { Filters, REGISTRY_STATUSES, RegistryList, RegistryTabs, StatusBadge, StatusChange, registryPath } from "./common";
import { UASTable } from "./uas";
import { byAt } from "./words";
import { PilotTable } from "./pilots";

export type Operator = components["schemas"]["RegistryOperator"];
type OperatorInput = components["schemas"]["RegistryOperatorInput"];
type OperatorPatch = components["schemas"]["RegistryOperatorPatch"];

const OPERATOR_TYPES = ["natural", "legal"] as const;
const SOURCES = ["manual", "portal", "uas_gov_ge_import"] as const;

export function OperatorsPage() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const [number, setNumber] = useState("");
  const [status, setStatus] = useState("");
  const [applied, setApplied] = useState({ number: "", status: "" });
  const c = columnsFor<Operator>();
  const cols = useMemo(
    () => [
      tableColumn<Operator, string>({
        id: "registration_number",
        accessorKey: "registration_number",
        header: () => t("authority.registry.f.registration_number"),
        cell: (ctx) => <span className="font-mono">{fmtRegistrationNumber(ctx.getValue())}</span>,
      }),
      c.enum("operator_type", "authority.registry.operator_type", { headerKey: "authority.registry.f.operator_type" }),
      tableColumn<Operator, string>({ id: "status", accessorKey: "status", header: () => t("authority.registry.f.status"), cell: (ctx) => <StatusBadge status={ctx.getValue()} /> }),
      c.utc("valid_until", { headerKey: "authority.registry.f.valid_until" }),
      c.enum("source", "authority.registry.source", { headerKey: "authority.registry.f.source" }),
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t],
  );
  const key = `operators|${applied.number}|${applied.status}`;
  return (
    <div className="flex flex-col" data-testid="operators-page">
      <PageHeader titleKey="authority.registry.operators.title">
        <Can roles={["registrar"]}>
          <Link href={registryPath(lang, "operators/new")} className="text-sm font-semibold underline" data-testid="operator-new">
            {t("authority.registry.operators.new")}
          </Link>
        </Can>
      </PageHeader>
      <RegistryTabs />
      <div className="flex flex-col gap-3 px-4 py-3">
        <Filters labelKey="authority.registry.filters" onApply={() => setApplied({ number: number.trim(), status })}>
          <div className="flex flex-col gap-1">
            <Label htmlFor="op-number">{t("authority.registry.search_number")}</Label>
            <Input id="op-number" value={number} maxLength={64} onChange={(e) => setNumber(e.target.value)} data-testid="search-number" />
          </div>
          <StatusFilter value={status} onChange={setStatus} />
        </Filters>
        <RegistryList<Operator>
          key={key}
          queryKey={key}
          read={async (cl, after) => {
            const d = must(
              await cl.GET("/v1/registry/operators", {
                params: {
                  query: {
                    ...(applied.number === "" ? {} : { number: applied.number }),
                    ...(applied.status === "" ? {} : { status: applied.status as Operator["status"] }),
                    ...(after === undefined ? {} : { after }),
                  },
                },
              }),
            );
            return { rows: d.operators, next: d.next_after };
          }}
          columns={cols}
          getRowId={(r) => r.id}
          captionKey="authority.registry.operators.title"
          emptyKey="authority.registry.operators.empty"
          onSelect={(r) => router.push(registryPath(lang, `operators/${encodeURIComponent(r.id)}`))}
          testId="operators"
        />
      </div>
    </div>
  );
}

export function StatusFilter({ value, onChange }: { value: string; onChange(v: string): void }) {
  const t = useT();
  return (
    <div className="flex flex-col gap-1">
      <Label htmlFor="status-filter">{t("authority.registry.f.status")}</Label>
      <select
        id="status-filter"
        className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1 text-sm"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="">{t("authority.registry.status_any")}</option>
        {REGISTRY_STATUSES.map((s) => (
          <option key={s} value={s}>
            {t(`authority.registry.status.${s}`)}
          </option>
        ))}
      </select>
    </div>
  );
}

export function OperatorDetail({ id }: { id: string }) {
  const { lang } = useLang();
  const client = useConsole();
  const { state, reload } = useLoad(`operator|${id}`, async (c) =>
    must(await c.GET("/v1/registry/operators/{operator_id}", { params: { path: { operator_id: id } } })),
  );
  const [editing, setEditing] = useState(false);
  const t = useT();
  return (
    <div className="flex flex-col" data-testid="operator-detail">
      <PageHeader titleKey="authority.registry.operators.detail" back={{ href: registryPath(lang, "operators"), labelKey: "authority.registry.operators.back" }} />
      <RegistryTabs />
      <Loaded state={state} testId="operator">
        {(op) => (
          <>
            <Section titleKey="authority.registry.facts">
              <Facts
                testId="operator-facts"
                items={[
                  ["authority.registry.f.registration_number", <span key="n" className="font-mono">{fmtRegistrationNumber(op.registration_number)}</span>],
                  ["authority.registry.f.operator_type", t(`authority.registry.operator_type.${op.operator_type}`)],
                  ["authority.registry.f.status", <StatusBadge key="s" status={op.status} />],
                  ["authority.registry.f.status_reason", op.status_reason],
                  ["authority.registry.f.has_secret_part", t(op.has_secret_part ? "common.yes" : "common.no")],
                  ["authority.registry.f.competency_confirmation", t(op.competency_confirmation ? "common.yes" : "common.no")],
                  ["authority.registry.f.authorisations", op.authorisations.length === 0 ? null : JSON.stringify(op.authorisations)],
                  ["authority.registry.f.valid_from", <UTC key="vf" iso={op.valid_from} />],
                  ["authority.registry.f.valid_until", <UTC key="vu" iso={op.valid_until} />],
                  ["authority.registry.f.source", t(`authority.registry.source.${op.source}`)],
                  ["authority.registry.f.registry_version", String(op.registry_version)],
                  ["authority.registry.f.created", byAt(t, lang, op.created_by, op.created_at)],
                  ["authority.registry.f.updated", byAt(t, lang, op.updated_by, op.updated_at)],
                ]}
              />
            </Section>
            <Section titleKey="authority.registry.status_title">
              <StatusChange
                subject={fmtRegistrationNumber(op.registration_number)}
                current={op.status}
                run={async (status, reason) =>
                  must(await client.POST("/v1/registry/operators/{operator_id}/status", { params: { path: { operator_id: id } }, body: { status, reason } }))
                }
                onDone={reload}
              />
            </Section>
            <div className="px-4 py-3">
              <PersonalData
                roles={["registrar", "inspector"]}
                testId="operator-pii"
                read={async (purpose) => must(await client.GET("/v1/registry/operators/{operator_id}/personal-data", { params: { path: { operator_id: id }, query: { purpose } } }))}
                rows={(p) => [
                  ["authority.registry.f.full_name", p.full_name],
                  ["authority.registry.f.legal_name", p.legal_name],
                  ["authority.registry.f.date_of_birth", p.date_of_birth],
                  ["authority.registry.f.legal_identification_number", p.legal_identification_number],
                  ["authority.registry.f.postal_address", p.postal_address],
                  ["authority.registry.f.contact_email", p.contact_email],
                  ["authority.registry.f.contact_phone", p.contact_phone],
                  ["authority.registry.f.insurance_policy_number", p.insurance_policy_number],
                ]}
              />
            </div>
            <Can roles={["registrar"]}>
              <Section titleKey="authority.registry.edit">
                {editing ? (
                  <OperatorForm
                    mode={{ kind: "edit", operator: op }}
                    onSaved={() => {
                      setEditing(false);
                      reload();
                    }}
                  />
                ) : (
                  <button type="button" className="self-start text-sm underline" onClick={() => setEditing(true)} data-testid="operator-edit">
                    {t("authority.registry.edit_open")}
                  </button>
                )}
              </Section>
            </Can>
            <Section titleKey="authority.registry.uas.of_operator">
              <UASTable operatorId={op.id} />
            </Section>
            <Section titleKey="authority.registry.pilots.of_operator">
              <PilotTable operatorId={op.id} />
            </Section>
          </>
        )}
      </Loaded>
    </div>
  );
}

/** The date of birth's shape (api: format date). */
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const opt = (max: number) => z.string().max(max).optional();

/** The authorisations' text as api's array of objects, or a message key. */
export function parseAuthorisations(text: string): { value: Record<string, unknown>[] } | { error: string } {
  if (text.trim() === "") return { value: [] };
  try {
    const v: unknown = JSON.parse(text);
    if (!Array.isArray(v) || v.some((x) => x === null || typeof x !== "object" || Array.isArray(x))) return { error: "authority.registry.authorisations_shape" };
    if (v.length > 100) return { error: "authority.registry.authorisations_many" };
    return { value: v as Record<string, unknown>[] };
  } catch {
    return { error: "authority.registry.authorisations_json" };
  }
}

function operatorSchema(create: boolean) {
  return z
    .object({
      operator_type: z.enum(OPERATOR_TYPES),
      registration_number: create ? z.string().trim().min(1).max(64) : z.string().optional(),
      secret_part: z.string().optional().refine((s) => s === undefined || s === "" || s.length === 3, { message: "authority.registry.secret_part_len" }),
      full_name: opt(200),
      legal_name: opt(200),
      date_of_birth: z.string().optional().refine((s) => s === undefined || s === "" || DATE.test(s), { message: "authority.registry.date_shape" }),
      legal_identification_number: opt(64),
      postal_address: create ? z.string().trim().min(1).max(500) : opt(500),
      contact_email: create ? z.string().trim().min(1).max(254) : opt(254),
      contact_phone: create ? z.string().trim().min(1).max(32) : opt(32),
      insurance_policy_number: opt(64),
      competency_confirmation: z.boolean(),
      authorisations: z.string().refine((s) => !("error" in parseAuthorisations(s)), { message: "authority.registry.authorisations_json" }),
      valid_from: shapes.utcTime().nullable().optional(),
      valid_until: create ? shapes.utcTime() : shapes.utcTime().nullable().optional(),
      source: z.enum(SOURCES),
    })
    .superRefine((v, ctx) => {
      // Art. 14(2)(a): a natural person's name and date of birth, a legal person's name and number.
      if (!create) return;
      if (v.operator_type === "natural") {
        if ((v.full_name ?? "").trim() === "") ctx.addIssue({ code: "custom", path: ["full_name"], message: "form.error.required" });
        if ((v.date_of_birth ?? "").trim() === "") ctx.addIssue({ code: "custom", path: ["date_of_birth"], message: "form.error.required" });
      } else {
        if ((v.legal_name ?? "").trim() === "") ctx.addIssue({ code: "custom", path: ["legal_name"], message: "form.error.required" });
        if ((v.legal_identification_number ?? "").trim() === "") ctx.addIssue({ code: "custom", path: ["legal_identification_number"], message: "form.error.required" });
      }
    });
}

type Mode = { kind: "create" } | { kind: "edit"; operator: Operator };

function PersonFields({ create }: { create: boolean }) {
  const type = useWatch({ name: "operator_type" }) as string;
  return type === "legal" ? (
    <>
      <TextField name="legal_name" labelKey="authority.registry.f.legal_name" required={create} />
      <TextField name="legal_identification_number" labelKey="authority.registry.f.legal_identification_number" required={create} />
      <CheckboxField name="competency_confirmation" labelKey="authority.registry.f.competency_confirmation" hintKey="authority.registry.h.competency_confirmation" />
    </>
  ) : (
    <>
      <TextField name="full_name" labelKey="authority.registry.f.full_name" required={create} />
      <TextField name="date_of_birth" labelKey="authority.registry.f.date_of_birth" hintKey="authority.registry.h.date" required={create} />
    </>
  );
}

/**
 * The Art. 14(2) field set. Registering sends every field; editing sends
 * only the fields the person filled in (a PATCH: personal data is never
 * read back into the form, so an empty box leaves the stored value).
 */
export function OperatorForm({ mode, onSaved }: { mode: Mode; onSaved(op: Operator): void }) {
  const client = useConsole();
  const create = mode.kind === "create";
  const schema = useMemo(() => operatorSchema(create), [create]);
  const defaults: z.input<typeof schema> = {
    operator_type: mode.kind === "edit" ? mode.operator.operator_type : "natural",
    registration_number: "",
    secret_part: "",
    full_name: "",
    legal_name: "",
    date_of_birth: "",
    legal_identification_number: "",
    postal_address: "",
    contact_email: "",
    contact_phone: "",
    insurance_policy_number: "",
    competency_confirmation: mode.kind === "edit" ? mode.operator.competency_confirmation : false,
    authorisations: mode.kind === "edit" && mode.operator.authorisations.length > 0 ? JSON.stringify(mode.operator.authorisations, null, 2) : "",
    valid_from: null,
    valid_until: mode.kind === "edit" ? mode.operator.valid_until : null,
    source: mode.kind === "edit" ? mode.operator.source : "manual",
  };
  return (
    <Form
      schema={schema}
      defaults={defaults}
      submitLabelKey={create ? "authority.registry.operators.register" : "authority.registry.save"}
      onSubmit={async (v) => {
        const auth = parseAuthorisations(v.authorisations);
        const authorisations = "value" in auth ? auth.value : [];
        if (mode.kind === "create") {
          const body = compact({ ...v, authorisations, valid_from: v.valid_from ?? undefined }) as OperatorInput;
          body.competency_confirmation = v.competency_confirmation;
          onSaved(must(await client.POST("/v1/registry/operators", { body })));
          return;
        }
        // Neither the type, the number, its secret part, the source nor the start of validity is changed by an edit (RegistryOperatorPatch).
        const rest = {
          full_name: v.full_name,
          legal_name: v.legal_name,
          date_of_birth: v.date_of_birth,
          legal_identification_number: v.legal_identification_number,
          postal_address: v.postal_address,
          contact_email: v.contact_email,
          contact_phone: v.contact_phone,
          insurance_policy_number: v.insurance_policy_number,
        };
        const body = compact({ ...rest, authorisations, valid_until: v.valid_until ?? undefined }) as OperatorPatch;
        body.competency_confirmation = v.competency_confirmation;
        if (authorisations.length === 0 && mode.operator.authorisations.length > 0) body.authorisations = [];
        onSaved(must(await client.PATCH("/v1/registry/operators/{operator_id}", { params: { path: { operator_id: mode.operator.id } }, body })));
      }}
    >
      <div className="grid gap-3 md:grid-cols-2" data-testid="operator-form">
        {create && <EnumField name="operator_type" values={OPERATOR_TYPES} i18nPrefix="authority.registry.operator_type" labelKey="authority.registry.f.operator_type" required />}
        {create && <TextField name="registration_number" labelKey="authority.registry.f.registration_number" hintKey="authority.registry.h.registration_number" required />}
        {create && <TextField name="secret_part" labelKey="authority.registry.f.secret_part" hintKey="authority.registry.h.secret_part" autoComplete="off" />}
        <PersonFields create={create} />
        <TextField name="postal_address" labelKey="authority.registry.f.postal_address" required={create} />
        <TextField name="contact_email" type="email" labelKey="authority.registry.f.contact_email" required={create} />
        <TextField name="contact_phone" type="tel" labelKey="authority.registry.f.contact_phone" required={create} />
        <TextField name="insurance_policy_number" labelKey="authority.registry.f.insurance_policy_number" />
        {create && <UTCDateTimeField name="valid_from" labelKey="authority.registry.f.valid_from" hintKey="authority.registry.h.valid_from" />}
        <UTCDateTimeField name="valid_until" labelKey="authority.registry.f.valid_until" required={create} />
        {create && <EnumField name="source" values={SOURCES} i18nPrefix="authority.registry.source" labelKey="authority.registry.f.source" required />}
        <TextareaField name="authorisations" labelKey="authority.registry.f.authorisations" hintKey="authority.registry.h.authorisations" className="md:col-span-2" />
      </div>
    </Form>
  );
}

export function OperatorNew() {
  const { lang } = useLang();
  const router = useRouter();
  return (
    <div className="flex flex-col" data-testid="operator-new-page">
      <PageHeader titleKey="authority.registry.operators.new" back={{ href: registryPath(lang, "operators"), labelKey: "authority.registry.operators.back" }} />
      <RegistryTabs />
      <div className="px-4 py-3">
        <Can roles={["registrar"]} fallback={<NotYourRole />}>
          <OperatorForm mode={{ kind: "create" }} onSaved={(op) => router.push(registryPath(lang, `operators/${encodeURIComponent(op.id)}`))} />
        </Can>
      </div>
    </div>
  );
}

/** A page whose act this session's roles do not hold; api would refuse it. */
export function NotYourRole() {
  const t = useT();
  return (
    <p className="m-0 text-sm" data-testid="not-your-role">
      {t("authority.act.not_your_role")}
    </p>
  );
}
