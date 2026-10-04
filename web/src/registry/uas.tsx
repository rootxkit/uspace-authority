"use client";

// Unmanned aircraft (api/openapi.yaml /v1/registry/uas*): the list with
// the look-up by serial, the detail, the form to register and to edit,
// and the status transition. No personal data is held on a UAS row.
import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { z } from "zod";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { EnumField, Form, NumberField, TextField } from "@rootxkit/uspace-ui/form";
import { columnsFor, tableColumn } from "@rootxkit/uspace-ui/table";
import { Input, Label } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { must, useConsole, useLoad } from "../authoring/api";
import { compact } from "../authoring/fields";
import { Can, Facts, Loaded, PageHeader, Section, UTC } from "../authoring/ui";
import { Filters, RegistryList, RegistryTabs, StatusBadge, StatusChange, registryPath } from "./common";
import { byAt } from "./words";
import { NotYourRole, StatusFilter } from "./operators";

export type UAS = components["schemas"]["RegistryUAS"];
type UASInput = components["schemas"]["RegistryUASInput"];
type UASPatch = components["schemas"]["RegistryUASPatch"];

export const CLASS_LABELS = ["C0", "C1", "C2", "C3", "C4", "C5", "C6"] as const;
export const RID_CAPABILITIES = ["direct", "network", "both", "none"] as const;

function useUASColumns() {
  const t = useT();
  const c = columnsFor<UAS>();
  return useMemo(
    () => [
      c.text("serial", { headerKey: "authority.registry.f.serial", mono: true }),
      c.text("manufacturer", { headerKey: "authority.registry.f.manufacturer" }),
      c.text("model", { headerKey: "authority.registry.f.model" }),
      c.text("class_label", { headerKey: "authority.registry.f.class_label" }),
      c.enum("rid_capability", "authority.registry.rid", { headerKey: "authority.registry.f.rid_capability" }),
      tableColumn<UAS, string>({ id: "status", accessorKey: "status", header: () => t("authority.registry.f.status"), cell: (ctx) => <StatusBadge status={ctx.getValue()} /> }),
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t],
  );
}

/** The UAS of one operator, or every UAS matching the filters. */
export function UASTable({ operatorId, serial = "", status = "" }: { operatorId?: string; serial?: string; status?: string }) {
  const { lang } = useLang();
  const router = useRouter();
  const cols = useUASColumns();
  const key = `uas|${operatorId ?? ""}|${serial}|${status}`;
  return (
    <RegistryList<UAS>
      key={key}
      queryKey={key}
      read={async (cl, after) => {
        const d = must(
          await cl.GET("/v1/registry/uas", {
            params: {
              query: {
                ...(operatorId === undefined ? {} : { operator_id: operatorId }),
                ...(serial === "" ? {} : { serial }),
                ...(status === "" ? {} : { status: status as UAS["status"] }),
                ...(after === undefined ? {} : { after }),
              },
            },
          }),
        );
        return { rows: d.uas, next: d.next_after };
      }}
      columns={cols}
      getRowId={(r) => r.id}
      captionKey="authority.registry.uas.title"
      emptyKey="authority.registry.uas.empty"
      onSelect={(r) => router.push(registryPath(lang, `uas/${encodeURIComponent(r.id)}`))}
      testId="uas"
    />
  );
}

export function UASPage() {
  const t = useT();
  const { lang } = useLang();
  const [serial, setSerial] = useState("");
  const [status, setStatus] = useState("");
  const [applied, setApplied] = useState({ serial: "", status: "" });
  return (
    <div className="flex flex-col" data-testid="uas-page">
      <PageHeader titleKey="authority.registry.uas.title">
        <Can roles={["registrar"]}>
          <Link href={registryPath(lang, "uas/new")} className="text-sm font-semibold underline" data-testid="uas-new">
            {t("authority.registry.uas.new")}
          </Link>
        </Can>
      </PageHeader>
      <RegistryTabs />
      <div className="flex flex-col gap-3 px-4 py-3">
        <Filters labelKey="authority.registry.filters" onApply={() => setApplied({ serial: serial.trim(), status })}>
          <div className="flex flex-col gap-1">
            <Label htmlFor="uas-serial">{t("authority.registry.search_serial")}</Label>
            <Input id="uas-serial" value={serial} maxLength={64} onChange={(e) => setSerial(e.target.value)} data-testid="search-serial" />
          </div>
          <StatusFilter value={status} onChange={setStatus} />
        </Filters>
        <UASTable serial={applied.serial} status={applied.status} />
      </div>
    </div>
  );
}

export function UASDetail({ id }: { id: string }) {
  const t = useT();
  const { lang } = useLang();
  const client = useConsole();
  const [editing, setEditing] = useState(false);
  const { state, reload } = useLoad(`uas|${id}`, async (c) => must(await c.GET("/v1/registry/uas/{uas_id}", { params: { path: { uas_id: id } } })));
  return (
    <div className="flex flex-col" data-testid="uas-detail">
      <PageHeader titleKey="authority.registry.uas.detail" back={{ href: registryPath(lang, "uas"), labelKey: "authority.registry.uas.back" }} />
      <RegistryTabs />
      <Loaded state={state} testId="uas-one">
        {(u) => (
          <>
            <Section titleKey="authority.registry.facts">
              <Facts
                testId="uas-facts"
                items={[
                  ["authority.registry.f.serial", <span key="s" className="font-mono">{u.serial}</span>],
                  ["authority.registry.f.manufacturer_code", u.manufacturer_code],
                  ["authority.registry.f.registration_mark", u.registration_mark],
                  ["authority.registry.f.manufacturer", u.manufacturer],
                  ["authority.registry.f.model", u.model],
                  ["authority.registry.f.class_label", u.class_label],
                  ["authority.registry.f.mtom_g", u.mtom_g === undefined ? null : t("authority.registry.grams", { g: u.mtom_g })],
                  ["authority.registry.f.rid_capability", t(`authority.registry.rid.${u.rid_capability}`)],
                  ["authority.registry.f.owner_ref", u.owner_ref],
                  [
                    "authority.registry.f.operator",
                    <Link key="o" className="underline" href={registryPath(lang, `operators/${encodeURIComponent(u.operator_id)}`)}>
                      {u.operator_id}
                    </Link>,
                  ],
                  ["authority.registry.f.status", <StatusBadge key="st" status={u.status} />],
                  ["authority.registry.f.status_reason", u.status_reason],
                  ["authority.registry.f.registered_at", <UTC key="r" iso={u.registered_at} />],
                  ["authority.registry.f.registry_version", String(u.registry_version)],
                  ["authority.registry.f.updated", byAt(t, lang, u.updated_by, u.updated_at)],
                ]}
              />
            </Section>
            <Section titleKey="authority.registry.status_title">
              <StatusChange
                subject={u.serial}
                current={u.status}
                run={async (status, reason) => must(await client.POST("/v1/registry/uas/{uas_id}/status", { params: { path: { uas_id: id } }, body: { status, reason } }))}
                onDone={reload}
              />
            </Section>
            <Can roles={["registrar"]}>
              <Section titleKey="authority.registry.edit">
                {editing ? (
                  <UASForm
                    mode={{ kind: "edit", uas: u }}
                    onSaved={() => {
                      setEditing(false);
                      reload();
                    }}
                  />
                ) : (
                  <button type="button" className="self-start text-sm underline" onClick={() => setEditing(true)} data-testid="uas-edit">
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

const optText = (max: number) => z.string().max(max).optional();

function uasSchema(create: boolean) {
  return z.object({
    operator_id: create ? z.string().trim().min(1).max(32) : z.string().optional(),
    serial: create ? z.string().trim().min(1).max(64) : z.string().optional(),
    registration_mark: optText(32),
    manufacturer: optText(100),
    model: optText(100),
    owner_ref: optText(64),
    class_label: z.enum(CLASS_LABELS).nullable().optional(),
    mtom_g: z.number().int().min(1).max(10_000_000).nullable().optional(),
    rid_capability: z.enum(RID_CAPABILITIES),
  });
}

type UASMode = { kind: "create"; operatorId?: string } | { kind: "edit"; uas: UAS };

export function UASForm({ mode, onSaved }: { mode: UASMode; onSaved(u: UAS): void }) {
  const client = useConsole();
  const create = mode.kind === "create";
  const schema = useMemo(() => uasSchema(create), [create]);
  const u = mode.kind === "edit" ? mode.uas : null;
  const defaults: z.input<typeof schema> = {
    operator_id: mode.kind === "create" ? (mode.operatorId ?? "") : "",
    serial: "",
    registration_mark: u?.registration_mark ?? "",
    manufacturer: u?.manufacturer ?? "",
    model: u?.model ?? "",
    owner_ref: u?.owner_ref ?? "",
    class_label: u?.class_label ?? null,
    mtom_g: u?.mtom_g ?? null,
    rid_capability: u?.rid_capability ?? "direct",
  };
  return (
    <Form
      schema={schema}
      defaults={defaults}
      submitLabelKey={create ? "authority.registry.uas.register" : "authority.registry.save"}
      onSubmit={async (v) => {
        if (mode.kind === "create") {
          onSaved(must(await client.POST("/v1/registry/uas", { body: compact(v) as UASInput })));
          return;
        }
        // The operator and the serial are not changed by an edit (RegistryUASPatch).
        const rest = { registration_mark: v.registration_mark, manufacturer: v.manufacturer, model: v.model, owner_ref: v.owner_ref, class_label: v.class_label, mtom_g: v.mtom_g, rid_capability: v.rid_capability };
        onSaved(must(await client.PATCH("/v1/registry/uas/{uas_id}", { params: { path: { uas_id: mode.uas.id } }, body: compact(rest) as UASPatch })));
      }}
    >
      <div className="grid gap-3 md:grid-cols-2" data-testid="uas-form">
        {create && <TextField name="operator_id" labelKey="authority.registry.f.operator" hintKey="authority.registry.h.operator_id" required />}
        {create && <TextField name="serial" labelKey="authority.registry.f.serial" hintKey="authority.registry.h.serial" required />}
        <TextField name="registration_mark" labelKey="authority.registry.f.registration_mark" />
        <TextField name="manufacturer" labelKey="authority.registry.f.manufacturer" />
        <TextField name="model" labelKey="authority.registry.f.model" />
        <TextField name="owner_ref" labelKey="authority.registry.f.owner_ref" hintKey="authority.registry.h.owner_ref" />
        <EnumField name="class_label" values={CLASS_LABELS} i18nPrefix="authority.registry.class" labelKey="authority.registry.f.class_label" />
        <NumberField name="mtom_g" labelKey="authority.registry.f.mtom_g" unit="authority.registry.unit.g" />
        <EnumField name="rid_capability" values={RID_CAPABILITIES} i18nPrefix="authority.registry.rid" labelKey="authority.registry.f.rid_capability" required />
      </div>
    </Form>
  );
}

export function UASNew() {
  const { lang } = useLang();
  const router = useRouter();
  return (
    <div className="flex flex-col" data-testid="uas-new-page">
      <PageHeader titleKey="authority.registry.uas.new" back={{ href: registryPath(lang, "uas"), labelKey: "authority.registry.uas.back" }} />
      <RegistryTabs />
      <div className="px-4 py-3">
        <Can roles={["registrar"]} fallback={<NotYourRole />}>
          <UASForm mode={{ kind: "create" }} onSaved={(u) => router.push(registryPath(lang, `uas/${encodeURIComponent(u.id)}`))} />
        </Can>
      </div>
    </div>
  );
}
