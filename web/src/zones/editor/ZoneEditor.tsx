"use client";

// The zone editor (WP-22): a form for every ED-318 property by its
// standard name (spec 09 §1.6), the geometry drawn on uspace-ui's map or
// typed, the vertical limits with their reference and unit, the
// applicability schedules (clock times or daylight events), the zone
// authority entries and the period of validity. In U-space mode the type
// is USPACE and the designation's form follows (src/zones/editor/
// DesignationFields.tsx). The form's field names are api's JSON paths
// (feature.properties.identifier, ...), so a refusal lands on its field;
// what lands nowhere is listed with its path. The feature is built by
// ./model.ts and judged by api with uspace-core; the editor checks only
// shape.
import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useFieldArray, useFormContext, useWatch } from "react-hook-form";
import { z } from "zod";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { EnumField, Form, NumberField, SelectField, TextField, UTCDateTimeField, shapes } from "@rootxkit/uspace-ui/form";
import type { FieldError, VerticalRef } from "@rootxkit/uspace-ui/model";
import { ApiError, fieldErrorsOf } from "@rootxkit/uspace-ui/api";
import { Button } from "@rootxkit/uspace-ui/ui";
import { useRuntimeConfig } from "../../components/Providers";
import { must, useConsole } from "../../authoring/api";
import { SetField, TextareaField } from "../../authoring/fields";
import { mapPath } from "../../shell/paths";
import type { ZoneVersion } from "../adapt";
import { DesignationFields, designationSchema } from "./DesignationFields";
import { designationOf, designationValues, DesignationProblem, type DesignationValues } from "./designation";
import { DrawingLayer } from "./DrawingLayer";
import { ZonesMap } from "../ZonesMap";
import {
  DAYS,
  EVENTS,
  EditorProblem,
  IDENTIFIER_MAX,
  PURPOSES,
  REASONS,
  TEXT_LANGS,
  UOMS,
  VARIANTS,
  VERTICAL_REFS,
  ZONE_TYPES,
  emptyAuthority,
  emptyDaily,
  emptyPeriod,
  emptyValues,
  extensionRefs,
  fromFeature,
  toFeature,
  type ZoneEditorValues,
} from "./model";

export type Dataset = "zones" | "uspace_airspace";

type Props = Omit<ZoneEditorValues, "geometry" | "layer">;
type Geometry = ZoneEditorValues["geometry"] & { layer: ZoneEditorValues["layer"] };

/** The form's values: the feature's members at their JSON paths, the period, and a U-space airspace's designation. */
export interface EditorForm {
  feature: { properties: Props; geometry: Geometry };
  from: string | null;
  to: string | null;
  designation: DesignationValues;
}

/** api's names of the period's two members, onto the form's (the rest of api's paths are the form's own). */
export function renameErrors(errors: readonly FieldError[]): FieldError[] {
  const names: Record<string, string> = { valid_from: "from", designated_from: "from", valid_to: "to", designated_to: "to" };
  return errors.map((e) => ({ field: names[e.field] ?? e.field, reason: e.reason }));
}

/** api's refusal with its field problems on the form's names; anything else is thrown on to the form. */
async function sent<T>(call: () => Promise<T>): Promise<T | FieldError[]> {
  try {
    return await call();
  } catch (err) {
    const errors = fieldErrorsOf(err);
    if (err instanceof ApiError && errors.length > 0) return renameErrors(errors);
    throw err;
  }
}

export function toForm(v: ZoneEditorValues, from: string | null, to: string | null, designation: DesignationValues): EditorForm {
  const { geometry, layer, ...properties } = v;
  return { feature: { properties, geometry: { ...geometry, layer } }, from, to, designation };
}

export function fromForm(f: EditorForm): ZoneEditorValues {
  const { layer, ...geometry } = f.feature.geometry;
  return { ...f.feature.properties, geometry, layer };
}

/** A kit select's value: null when nothing is chosen (the kit's SelectField), "" for the model. */
const choice = z
  .string()
  .nullable()
  .transform((v) => v ?? "");
const chosen = (max: number) => choice.pipe(z.string().min(1).max(max));
const text = z.object({ text: z.string().max(200), lang: chosen(5) });
const opt = (max: number) => z.string().max(max);

function editorSchema(dataset: Dataset) {
  return z.object({
    feature: z.object({
      properties: z.object({
        identifier: z.string().trim().min(1).max(IDENTIFIER_MAX),
        country: z.string().trim().regex(/^[A-Z]{3}$/, { message: "authority.zone.e.country" }),
        name: z.array(text).max(20),
        type: dataset === "uspace_airspace" ? z.literal("USPACE") : z.enum(ZONE_TYPES.filter((x) => x !== "USPACE") as [string, ...string[]]),
        variant: choice,
        restrictionConditions: opt(1000),
        region: z.number().int().min(0).max(65535).nullable(),
        reason: z.array(z.string()).max(9),
        otherReasonInfo: z.array(text).max(20),
        regulationExemption: choice,
        message: z.array(text).max(20),
        extendedProperties: z.string().max(100_000),
        limitedApplicability: z
          .array(
            z.object({
              startDateTime: shapes.utcTime().nullable(),
              endDateTime: shapes.utcTime().nullable(),
              schedule: z
                .array(
                  z.object({
                    day: z.array(z.string()).min(1),
                    start: z.enum(["time", "event"]),
                    startTime: z.string(),
                    startEvent: z.string(),
                    end: z.enum(["time", "event"]),
                    endTime: z.string(),
                    endEvent: z.string(),
                  }),
                )
                .max(50),
            }),
          )
          .max(50),
        zoneAuthority: z
          .array(
            z.object({
              lang: chosen(5),
              name: opt(200),
              service: opt(200),
              contactName: opt(200),
              siteURL: opt(2048),
              email: opt(254),
              phone: opt(64),
              purpose: z.enum(PURPOSES),
              intervalBefore: opt(64),
            }),
          )
          .max(20),
        dataSource: z.object({
          creationDateTime: shapes.utcTime().nullable(),
          updateDateTime: shapes.utcTime().nullable(),
          originatorText: opt(200),
          originatorLang: z.string().max(5),
        }),
      }),
      geometry: z.object({
        kind: z.enum(["polygon", "circle"]),
        rings: z.string().max(400_000),
        centerLng: z.number().min(-180).max(180).nullable(),
        centerLat: z.number().min(-90).max(90).nullable(),
        radiusM: z.number().positive().nullable(),
        layer: z.object({
          lower: z.number().nullable(),
          lowerReference: choice,
          upper: z.number().nullable(),
          upperReference: choice,
          uom: z.enum(UOMS),
        }),
      }),
    }),
    from: shapes.utcTime(),
    to: shapes.utcTime(),
    designation: dataset === "uspace_airspace" ? designationSchema : z.any(),
  });
}

const LANG_OPTIONS = TEXT_LANGS.map((l) => ({ value: l, labelKey: `authority.zone.lang.${l}` }));

function TextList({ name, labelKey, testId }: { name: string; labelKey: string; testId: string }) {
  const t = useT();
  const { fields, append, remove } = useFieldArray({ name });
  return (
    <fieldset className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2" data-testid={testId}>
      <legend className="px-1 text-sm font-semibold">{t(labelKey)}</legend>
      {fields.map((f, i) => (
        <div key={f.id} className="grid items-end gap-2 md:grid-cols-[1fr_10rem_auto]">
          <TextField name={`${name}.${i}.text`} labelKey="authority.zone.f.text" />
          <SelectField name={`${name}.${i}.lang`} labelKey="authority.zone.f.lang" options={LANG_OPTIONS} />
          <Button type="button" size="sm" variant="outline" onClick={() => remove(i)}>
            {t("authority.act.remove")}
          </Button>
        </div>
      ))}
      <Button type="button" size="sm" variant="outline" className="self-start" onClick={() => append({ text: "", lang: "en-GB" })}>
        {t("authority.act.add")}
      </Button>
    </fieldset>
  );
}

function Schedule({ name }: { name: string }) {
  const t = useT();
  const { fields, append, remove } = useFieldArray({ name });
  const values = useWatch({ name }) as ZoneEditorValues["limitedApplicability"][number]["schedule"] | undefined;
  return (
    <fieldset className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2">
      <legend className="px-1 text-sm">{t("authority.zone.f.schedule")}</legend>
      {fields.map((f, i) => {
        const d = values?.[i];
        return (
          <div key={f.id} className="flex flex-col gap-2 border-b border-[var(--us-border)] pb-2" data-testid="schedule-entry">
            <SetField name={`${name}.${i}.day`} values={DAYS} i18nPrefix="authority.zone.day" labelKey="authority.zone.f.day" required />
            <div className="grid gap-2 md:grid-cols-4">
              <SelectField
                name={`${name}.${i}.start`}
                labelKey="authority.zone.f.start_by"
                options={[
                  { value: "time", labelKey: "authority.zone.by_time" },
                  { value: "event", labelKey: "authority.zone.by_event" },
                ]}
              />
              {d?.start === "event" ? (
                <EnumField name={`${name}.${i}.startEvent`} values={EVENTS} i18nPrefix="authority.zone.event" labelKey="authority.zone.f.startEvent" required />
              ) : (
                <TextField name={`${name}.${i}.startTime`} labelKey="authority.zone.f.startTime" hintKey="authority.zone.h.time" required />
              )}
              <SelectField
                name={`${name}.${i}.end`}
                labelKey="authority.zone.f.end_by"
                options={[
                  { value: "time", labelKey: "authority.zone.by_time" },
                  { value: "event", labelKey: "authority.zone.by_event" },
                ]}
              />
              {d?.end === "event" ? (
                <EnumField name={`${name}.${i}.endEvent`} values={EVENTS} i18nPrefix="authority.zone.event" labelKey="authority.zone.f.endEvent" required />
              ) : (
                <TextField name={`${name}.${i}.endTime`} labelKey="authority.zone.f.endTime" hintKey="authority.zone.h.time" required />
              )}
            </div>
            <Button type="button" size="sm" variant="outline" className="self-start" onClick={() => remove(i)}>
              {t("authority.act.remove")}
            </Button>
          </div>
        );
      })}
      <Button type="button" size="sm" variant="outline" className="self-start" onClick={() => append(emptyDaily())} data-testid="schedule-add">
        {t("authority.zone.schedule_add")}
      </Button>
    </fieldset>
  );
}

function Applicability() {
  const t = useT();
  const name = "feature.properties.limitedApplicability";
  const { fields, append, remove } = useFieldArray({ name });
  return (
    <fieldset className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2" data-testid="applicability">
      <legend className="px-1 text-sm font-semibold">{t("authority.zone.f.limitedApplicability")}</legend>
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("authority.zone.h.limitedApplicability")}</p>
      {fields.map((f, i) => (
        <div key={f.id} className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2">
          <div className="grid gap-2 md:grid-cols-2">
            <UTCDateTimeField name={`${name}.${i}.startDateTime`} labelKey="authority.zone.f.startDateTime" seconds />
            <UTCDateTimeField name={`${name}.${i}.endDateTime`} labelKey="authority.zone.f.endDateTime" seconds />
          </div>
          <Schedule name={`${name}.${i}.schedule`} />
          <Button type="button" size="sm" variant="outline" className="self-start" onClick={() => remove(i)}>
            {t("authority.zone.period_remove")}
          </Button>
        </div>
      ))}
      <Button type="button" size="sm" variant="outline" className="self-start" onClick={() => append(emptyPeriod())} data-testid="period-add">
        {t("authority.zone.period_add")}
      </Button>
    </fieldset>
  );
}

function Authorities() {
  const t = useT();
  const name = "feature.properties.zoneAuthority";
  const { fields, append, remove } = useFieldArray({ name });
  return (
    <fieldset className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2" data-testid="authorities">
      <legend className="px-1 text-sm font-semibold">{t("authority.zone.f.zoneAuthority")}</legend>
      {fields.map((f, i) => (
        <div key={f.id} className="grid gap-2 rounded border border-[var(--us-border)] p-2 md:grid-cols-3">
          <SelectField name={`${name}.${i}.lang`} labelKey="authority.zone.f.authority_lang" options={LANG_OPTIONS} />
          <TextField name={`${name}.${i}.name`} labelKey="authority.zone.f.authority_name" />
          <TextField name={`${name}.${i}.service`} labelKey="authority.zone.f.service" />
          <TextField name={`${name}.${i}.contactName`} labelKey="authority.zone.f.contactName" />
          <TextField name={`${name}.${i}.siteURL`} type="url" labelKey="authority.zone.f.siteURL" />
          <TextField name={`${name}.${i}.email`} type="email" labelKey="authority.zone.f.email" />
          <TextField name={`${name}.${i}.phone`} type="tel" labelKey="authority.zone.f.phone" />
          <EnumField name={`${name}.${i}.purpose`} values={PURPOSES} i18nPrefix="authority.zone.purpose" labelKey="authority.zone.f.purpose" required />
          <TextField name={`${name}.${i}.intervalBefore`} labelKey="authority.zone.f.intervalBefore" hintKey="authority.zone.h.intervalBefore" />
          <Button type="button" size="sm" variant="outline" className="self-end" onClick={() => remove(i)}>
            {t("authority.act.remove")}
          </Button>
        </div>
      ))}
      <Button type="button" size="sm" variant="outline" className="self-start" onClick={() => append(emptyAuthority("en-GB"))}>
        {t("authority.zone.authority_add")}
      </Button>
    </fieldset>
  );
}

function GeometryFields({ context }: { context: readonly ZoneVersion[] }) {
  const t = useT();
  const { setValue, getValues } = useFormContext<EditorForm>();
  const geometry = useWatch<EditorForm, "feature.geometry">({ name: "feature.geometry" });
  const ext = extensionRefs(geometry.layer);
  return (
    <fieldset className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2" data-testid="geometry">
      <legend className="px-1 text-sm font-semibold">{t("authority.zone.f.geometry")}</legend>
      <SelectField
        name="feature.geometry.kind"
        labelKey="authority.zone.f.geometry_kind"
        options={[
          { value: "polygon", labelKey: "authority.zone.kind.polygon" },
          { value: "circle", labelKey: "authority.zone.kind.circle" },
        ]}
      />
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t(geometry.kind === "circle" ? "authority.zone.h.circle_draw" : "authority.zone.h.polygon_draw")}</p>
      <ZonesMap zones={context} testId="editor-map">
        <DrawingLayer
          geometry={geometry}
          onClick={(lng, lat) => {
            if (getValues("feature.geometry.kind") === "circle") {
              setValue("feature.geometry.centerLng", lng, { shouldDirty: true });
              setValue("feature.geometry.centerLat", lat, { shouldDirty: true });
            } else {
              const cur = getValues("feature.geometry.rings");
              setValue("feature.geometry.rings", `${cur.trimEnd()}${cur.trim() === "" ? "" : "\n"}${lng} ${lat}`, { shouldDirty: true });
            }
          }}
        />
      </ZonesMap>
      {geometry.kind === "circle" ? (
        <div className="grid gap-2 md:grid-cols-3" data-testid="circle-fields">
          <NumberField name="feature.geometry.centerLng" labelKey="authority.zone.f.center_lng" unit="form.unit.deg" required />
          <NumberField name="feature.geometry.centerLat" labelKey="authority.zone.f.center_lat" unit="form.unit.deg" required />
          <NumberField name="feature.geometry.radiusM" labelKey="authority.zone.f.radius" unit="form.unit.m" hintKey="authority.zone.h.radius" required />
          <p className="m-0 text-xs md:col-span-3">{t("authority.zone.circle_not_drawn")}</p>
        </div>
      ) : (
        <TextareaField name="feature.geometry.rings" labelKey="authority.zone.f.rings" hintKey="authority.zone.h.rings" rows={8} required />
      )}
      <div className="grid gap-2 md:grid-cols-5" data-testid="layer-fields">
        <NumberField name="feature.geometry.layer.lower" labelKey="authority.zone.f.lower" datum={(VERTICAL_REFS as readonly string[]).includes(geometry.layer.lowerReference) ? (geometry.layer.lowerReference as VerticalRef) : null} />
        <EnumField name="feature.geometry.layer.lowerReference" values={VERTICAL_REFS} i18nPrefix="authority.zone.ref" labelKey="authority.zone.f.lowerReference" />
        <NumberField name="feature.geometry.layer.upper" labelKey="authority.zone.f.upper" datum={(VERTICAL_REFS as readonly string[]).includes(geometry.layer.upperReference) ? (geometry.layer.upperReference as VerticalRef) : null} />
        <EnumField name="feature.geometry.layer.upperReference" values={VERTICAL_REFS} i18nPrefix="authority.zone.ref" labelKey="authority.zone.f.upperReference" />
        <EnumField name="feature.geometry.layer.uom" values={UOMS} i18nPrefix="authority.zone.uom" labelKey="authority.zone.f.uom" hintKey="authority.zone.h.uom" required />
      </div>
      {ext.length > 0 && (
        <p role="note" className="m-0 rounded border border-[var(--us-severity-warning)] p-2 text-xs" data-testid="wgs84-extension">
          {t("authority.zone.wgs84_extension")}
        </p>
      )}
      <p className="m-0 text-xs text-[var(--us-text-muted)]" data-testid="unverified-note">
        {t("authority.zone.unverified_note")}
      </p>
    </fieldset>
  );
}

export interface ZoneEditorProps {
  dataset: Dataset;
  /** The version revised; absent for a new zone. */
  revising?: ZoneVersion;
  /** Zones drawn beside the one being authored. */
  context: readonly ZoneVersion[];
}

/** The path of a zone's or U-space airspace's page. */
export function zonePath(lang: string, dataset: Dataset, identifier: string): string {
  return `${mapPath(lang)}/${dataset === "zones" ? "zones" : "uspace"}/${encodeURIComponent(identifier)}`;
}

export function ZoneEditor({ dataset, revising, context }: ZoneEditorProps) {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const client = useConsole();
  const cfg = useRuntimeConfig();
  const schema = useMemo(() => editorSchema(dataset), [dataset]);
  const [initial] = useState(() => {
    const usp = dataset === "uspace_airspace";
    if (revising === undefined) {
      return { ok: true as const, values: emptyValues({ country: cfg.zoneCountry, ...(usp ? { type: "USPACE" as const } : {}) }), extra: {} };
    }
    const r = fromFeature(revising.feature, cfg.zoneCountry, usp ? ["uspace_requirements"] : []);
    return r.editable ? { ok: true as const, values: r.values, extra: r.extra } : { ok: false as const };
  });
  if (!initial.ok) {
    return (
      <p role="status" className="m-0 px-4 py-3 text-sm" data-testid="not-editable">
        {t("authority.zone.not_editable")}
      </p>
    );
  }
  const defaults = toForm(initial.values, revising?.valid_from ?? null, revising?.valid_to ?? null, designationValues(revising?.designation));
  return (
    <div className="px-4 py-3" data-testid="zone-editor">
      <Form
        schema={schema}
        defaults={defaults as never}
        submitLabelKey={revising === undefined ? "authority.zone.save_draft" : "authority.zone.save_revision"}
        onSubmit={async (raw) => {
          const f = raw as unknown as EditorForm;
          let feature: Record<string, unknown>;
          try {
            feature = toFeature(fromForm(f), initial.extra);
          } catch (e) {
            if (e instanceof EditorProblem) return [{ field: `feature.${e.field}`, reason: t(e.key) }] satisfies FieldError[];
            throw e;
          }
          const id = revising?.identifier;
          if (dataset === "zones") {
            const body = { feature: feature as ZoneVersion["feature"], valid_from: f.from as string, valid_to: f.to as string };
            const v = await sent(async () =>
              id === undefined
                ? must(await client.POST("/v1/zones", { body }))
                : must(await client.PUT("/v1/zones/{identifier}", { params: { path: { identifier: id } }, body })),
            );
            if (Array.isArray(v)) return v;
            router.push(zonePath(lang, dataset, v.identifier));
            return;
          }
          let designation;
          try {
            designation = designationOf(f.designation);
          } catch (e) {
            if (e instanceof DesignationProblem) return [{ field: `designation.${e.field}`, reason: t(e.key) }] satisfies FieldError[];
            throw e;
          }
          const body = { feature: feature as ZoneVersion["feature"], designated_from: f.from as string, designated_to: f.to as string, designation };
          const v = await sent(async () =>
            id === undefined
              ? must(await client.POST("/v1/uspace", { body }))
              : must(await client.PUT("/v1/uspace/{identifier}", { params: { path: { identifier: id } }, body })),
          );
          if (Array.isArray(v)) return v;
          router.push(zonePath(lang, dataset, v.identifier));
        }}
      >
        <div className="flex flex-col gap-3">
          <fieldset className="grid gap-2 rounded border border-[var(--us-border)] p-2 md:grid-cols-3" data-testid="zone-identity">
            <legend className="px-1 text-sm font-semibold">{t("authority.zone.identity")}</legend>
            <TextField name="feature.properties.identifier" labelKey="authority.zone.f.identifier" hintKey="authority.zone.h.identifier" required disabled={revising !== undefined} />
            <TextField name="feature.properties.country" labelKey="authority.zone.f.country" hintKey="authority.zone.h.country" required />
            {dataset === "zones" ? (
              <EnumField name="feature.properties.type" values={ZONE_TYPES.filter((x) => x !== "USPACE")} i18nPrefix="zone.type" labelKey="authority.zone.f.type" required />
            ) : (
              <p className="m-0 self-end text-sm">{t("authority.zone.type_uspace")}</p>
            )}
            <EnumField name="feature.properties.variant" values={VARIANTS} i18nPrefix="authority.zone.variant" labelKey="authority.zone.f.variant" />
            <TextField name="feature.properties.restrictionConditions" labelKey="authority.zone.f.restrictionConditions" />
            <NumberField name="feature.properties.region" labelKey="authority.zone.f.region" />
            <EnumField name="feature.properties.regulationExemption" values={["YES", "NO"]} i18nPrefix="authority.zone.yesno" labelKey="authority.zone.f.regulationExemption" />
            <SetField name="feature.properties.reason" values={REASONS} i18nPrefix="authority.zone.reason" labelKey="authority.zone.f.reason" className="md:col-span-3" />
          </fieldset>
          <TextList name="feature.properties.name" labelKey="authority.zone.f.name" testId="names" />
          <TextList name="feature.properties.otherReasonInfo" labelKey="authority.zone.f.otherReasonInfo" testId="other-reasons" />
          <TextList name="feature.properties.message" labelKey="authority.zone.f.message" testId="messages" />
          <GeometryFields context={context} />
          <fieldset className="grid gap-2 rounded border border-[var(--us-border)] p-2 md:grid-cols-2" data-testid="validity">
            <legend className="px-1 text-sm font-semibold">{t(dataset === "zones" ? "authority.zone.validity" : "authority.uspace.designated")}</legend>
            <UTCDateTimeField name="from" labelKey={dataset === "zones" ? "authority.zone.f.valid_from" : "authority.uspace.f.designated_from"} required />
            <UTCDateTimeField name="to" labelKey={dataset === "zones" ? "authority.zone.f.valid_to" : "authority.uspace.f.designated_to"} required />
          </fieldset>
          <Applicability />
          <Authorities />
          {dataset === "uspace_airspace" && <DesignationFields />}
          <fieldset className="grid gap-2 rounded border border-[var(--us-border)] p-2 md:grid-cols-3">
            <legend className="px-1 text-sm font-semibold">{t("authority.zone.f.dataSource")}</legend>
            <UTCDateTimeField name="feature.properties.dataSource.creationDateTime" labelKey="authority.zone.f.creationDateTime" seconds />
            <UTCDateTimeField name="feature.properties.dataSource.updateDateTime" labelKey="authority.zone.f.updateDateTime" seconds />
            <TextField name="feature.properties.dataSource.originatorText" labelKey="authority.zone.f.originator" />
          </fieldset>
          <TextareaField name="feature.properties.extendedProperties" labelKey="authority.zone.f.extendedProperties" hintKey={dataset === "zones" ? "authority.zone.h.extendedProperties" : "authority.uspace.h.extendedProperties"} rows={4} />
        </div>
      </Form>
    </div>
  );
}
