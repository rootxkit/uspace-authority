"use client";

// The U-space airspace's designation (spec 03 §1, 2021/664 Art. 3(4);
// api/openapi.yaml USpaceDesignation): the name, the services required,
// the Art. 3(4) block (UAS requirements, operational conditions, service
// performance, airspace constraints), the adjacent airspaces, whether it
// lies in controlled airspace, and the designation and AIP references.
import { z } from "zod";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { CheckboxField, NumberField, TextField } from "@rootxkit/uspace-ui/form";
import { SetField, TextareaField } from "../../authoring/fields";
import { USPACE_SERVICES, USPACE_SERVICES_MIN } from "./designation";

const positive = z.number().positive().nullable();

export const designationSchema = z.object({
  airspace_name: z.string().trim().min(1).max(200),
  services_required: z.array(z.string()).min(USPACE_SERVICES_MIN, { message: "authority.uspace.e.services" }).max(USPACE_SERVICES.length),
  uas_requirements: z.string().max(100_000),
  operational_conditions: z.string().max(100_000),
  nid_update_hz: z.number().positive(),
  ti_update_hz: z.number().positive(),
  cis_latency_s: z.number().positive(),
  service_performance_extra: z.string().max(100_000),
  max_height_agl_m: positive,
  airspace_constraints_extra: z.string().max(100_000),
  adjacent_ids: z.string().max(10_000),
  risk_assessment_ref: z.string().max(200),
  in_controlled_airspace: z.boolean(),
  ats_provider_id: z.string().max(64),
  cisp_id: z.string().max(64),
  designation_ref: z.string().max(200),
  aip_ref: z.string().max(200),
});

export function DesignationFields() {
  const t = useT();
  return (
    <fieldset className="flex flex-col gap-2 rounded border border-[var(--us-border)] p-2" data-testid="designation">
      <legend className="px-1 text-sm font-semibold">{t("authority.uspace.designation")}</legend>
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("authority.uspace.designation_intro")}</p>
      <div className="grid gap-2 md:grid-cols-2">
        <TextField name="designation.airspace_name" labelKey="authority.uspace.f.airspace_name" required />
        <CheckboxField name="designation.in_controlled_airspace" labelKey="authority.uspace.f.in_controlled_airspace" />
      </div>
      <SetField name="designation.services_required" values={USPACE_SERVICES} i18nPrefix="authority.uspace.service" labelKey="authority.uspace.f.services_required" hintKey="authority.uspace.h.services_required" required />
      <fieldset className="grid gap-2 rounded border border-[var(--us-border)] p-2 md:grid-cols-2">
        <legend className="px-1 text-sm">{t("authority.uspace.art34")}</legend>
        <TextareaField name="designation.uas_requirements" labelKey="authority.uspace.f.uas_requirements" hintKey="authority.uspace.h.json_object" rows={3} />
        <TextareaField name="designation.operational_conditions" labelKey="authority.uspace.f.operational_conditions" hintKey="authority.uspace.h.json_object" rows={3} />
        <NumberField name="designation.nid_update_hz" labelKey="authority.uspace.f.nid_update_hz" unit="authority.uspace.unit.hz" required />
        <NumberField name="designation.ti_update_hz" labelKey="authority.uspace.f.ti_update_hz" unit="authority.uspace.unit.hz" required />
        <NumberField name="designation.cis_latency_s" labelKey="authority.uspace.f.cis_latency_s" unit="form.unit.s" required />
        <TextareaField name="designation.service_performance_extra" labelKey="authority.uspace.f.service_performance_extra" hintKey="authority.uspace.h.json_object" rows={2} />
        <NumberField name="designation.max_height_agl_m" labelKey="authority.uspace.f.max_height_agl_m" unit="form.unit.m" datum="AGL" />
        <TextareaField name="designation.airspace_constraints_extra" labelKey="authority.uspace.f.airspace_constraints_extra" hintKey="authority.uspace.h.json_object" rows={2} />
      </fieldset>
      <div className="grid gap-2 md:grid-cols-3">
        <TextField name="designation.adjacent_ids" labelKey="authority.uspace.f.adjacent_ids" hintKey="authority.uspace.h.adjacent_ids" />
        <TextField name="designation.ats_provider_id" labelKey="authority.uspace.f.ats_provider_id" />
        <TextField name="designation.cisp_id" labelKey="authority.uspace.f.cisp_id" />
        <TextField name="designation.designation_ref" labelKey="authority.uspace.f.designation_ref" />
        <TextField name="designation.aip_ref" labelKey="authority.uspace.f.aip_ref" />
        <TextField name="designation.risk_assessment_ref" labelKey="authority.uspace.f.risk_assessment_ref" />
      </div>
    </fieldset>
  );
}
