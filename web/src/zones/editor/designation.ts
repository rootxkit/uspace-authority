// A U-space airspace's designation (spec 03 §1; 2021/664 Art. 3 and 5;
// api/openapi.yaml USpaceDesignation): the form's values and the object
// api is sent. api writes the Art. 3(4) block into the feature's
// extendedProperties.uspace_requirements itself (docs/runbooks/zones.md);
// the editor never does.
import type { components } from "../../api/types";

export type Designation = components["schemas"]["USpaceDesignation"];

/** The services a designation may require (USpaceDesignation.services_required; at least four). */
export const USPACE_SERVICES = ["NID", "GEO", "FA", "TI", "WX", "CM"] as const;
/** api's minimum of services_required. */
export const USPACE_SERVICES_MIN = 4;

export interface DesignationValues {
  airspace_name: string;
  services_required: string[];
  /** Art. 3(4)(a), a JSON object. */
  uas_requirements: string;
  /** Art. 3(4)(b), a JSON object. */
  operational_conditions: string;
  /** Art. 3(4)(c): the three required members, and any other as JSON. */
  nid_update_hz: number | null;
  ti_update_hz: number | null;
  cis_latency_s: number | null;
  service_performance_extra: string;
  /** Art. 3(4)(d): the height ceiling, and any other member as JSON. */
  max_height_agl_m: number | null;
  airspace_constraints_extra: string;
  /** Identifiers of the adjacent U-space airspaces, comma separated. */
  adjacent_ids: string;
  risk_assessment_ref: string;
  in_controlled_airspace: boolean;
  ats_provider_id: string;
  cisp_id: string;
  designation_ref: string;
  aip_ref: string;
}

export function emptyDesignation(): DesignationValues {
  return {
    airspace_name: "",
    services_required: [],
    uas_requirements: "",
    operational_conditions: "",
    nid_update_hz: null,
    ti_update_hz: null,
    cis_latency_s: null,
    service_performance_extra: "",
    max_height_agl_m: null,
    airspace_constraints_extra: "",
    adjacent_ids: "",
    risk_assessment_ref: "",
    in_controlled_airspace: false,
    ats_provider_id: "",
    cisp_id: "",
    designation_ref: "",
    aip_ref: "",
  };
}

export class DesignationProblem extends Error {
  constructor(
    readonly field: string,
    readonly key: string,
  ) {
    super(`${field}: ${key}`);
  }
}

function object(text: string, field: string): Record<string, unknown> {
  if (text.trim() === "") return {};
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new DesignationProblem(field, "authority.uspace.e.json");
  }
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new DesignationProblem(field, "authority.uspace.e.object");
  return v as Record<string, unknown>;
}

const opt = (s: string) => (s.trim() === "" ? undefined : s.trim());

/** The designation api takes, from the form's values; every required member present, the empty optional ones left out. */
export function designationOf(v: DesignationValues): Designation {
  const perf: Record<string, unknown> = { ...object(v.service_performance_extra, "service_performance_extra") };
  if (v.nid_update_hz !== null) perf["nid_update_hz"] = v.nid_update_hz;
  if (v.ti_update_hz !== null) perf["ti_update_hz"] = v.ti_update_hz;
  if (v.cis_latency_s !== null) perf["cis_latency_s"] = v.cis_latency_s;
  const constraints: Record<string, unknown> = { ...object(v.airspace_constraints_extra, "airspace_constraints_extra") };
  if (v.max_height_agl_m !== null) constraints["max_height_agl_m"] = v.max_height_agl_m;
  const adjacent = v.adjacent_ids
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s !== "");
  const d: Designation = {
    airspace_name: v.airspace_name.trim(),
    services_required: USPACE_SERVICES.filter((s) => v.services_required.includes(s)),
    uas_requirements: object(v.uas_requirements, "uas_requirements"),
    service_performance: perf as Designation["service_performance"],
    operational_conditions: object(v.operational_conditions, "operational_conditions"),
    airspace_constraints: constraints,
    in_controlled_airspace: v.in_controlled_airspace,
  };
  if (adjacent.length > 0) d.adjacent_ids = adjacent;
  const refs = { risk_assessment_ref: opt(v.risk_assessment_ref), ats_provider_id: opt(v.ats_provider_id), cisp_id: opt(v.cisp_id), designation_ref: opt(v.designation_ref), aip_ref: opt(v.aip_ref) };
  for (const [k, x] of Object.entries(refs)) if (x !== undefined) (d as unknown as Record<string, unknown>)[k] = x;
  return d;
}

/** The form's values of a stored designation. */
export function designationValues(d: Designation | undefined): DesignationValues {
  if (d === undefined) return emptyDesignation();
  const { nid_update_hz, ti_update_hz, cis_latency_s, ...perfRest } = d.service_performance;
  const { max_height_agl_m, ...consRest } = d.airspace_constraints as { max_height_agl_m?: number } & Record<string, unknown>;
  const json = (o: Record<string, unknown>) => (Object.keys(o).length === 0 ? "" : JSON.stringify(o, null, 2));
  return {
    airspace_name: d.airspace_name,
    services_required: [...d.services_required],
    uas_requirements: json(d.uas_requirements),
    operational_conditions: json(d.operational_conditions),
    nid_update_hz,
    ti_update_hz,
    cis_latency_s,
    service_performance_extra: json(perfRest),
    max_height_agl_m: max_height_agl_m ?? null,
    airspace_constraints_extra: json(consRest),
    adjacent_ids: (d.adjacent_ids ?? []).join(", "),
    risk_assessment_ref: d.risk_assessment_ref ?? "",
    in_controlled_airspace: d.in_controlled_airspace,
    ats_provider_id: d.ats_provider_id ?? "",
    cisp_id: d.cisp_id ?? "",
    designation_ref: d.designation_ref ?? "",
    aip_ref: d.aip_ref ?? "",
  };
}
