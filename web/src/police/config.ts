// The police realm's purposes as the console offers them (WP-23). api is
// the authority on them (POLICE_PURPOSES, POLICE_PII_PURPOSES; WP-19): a
// purpose off its list is refused there, whatever this offers. The
// console's lists are configuration with the spec's defaults, **pending
// GCAA** (spec Q8, plan Q-A14: the legal basis and the access levels are
// the authority's and the DPO's to decide), and must equal api's.
//
//   WEB_POLICE_PURPOSES      public_order,traffic_enforcement,criminal_investigation,security_threat
//   WEB_POLICE_PII_PURPOSES  criminal_investigation,security_threat
//
// The same rules as api's: lower-case codes ([a-z][a-z0-9_]{0,63}), no
// repeat, every personal-data purpose on the first list. A malformed list
// is a problem naming the variable, and the realm's forms offer nothing
// (fail closed).

/** The spec's default purposes (docs/runbooks/police-realm.md), pending GCAA. */
export const DEFAULT_POLICE_PURPOSES: readonly string[] = ["public_order", "traffic_enforcement", "criminal_investigation", "security_threat"];
/** The spec's default personal-data purposes, pending GCAA. */
export const DEFAULT_POLICE_PII_PURPOSES: readonly string[] = ["criminal_investigation", "security_threat"];

const CODE = /^[a-z][a-z0-9_]{0,63}$/;

export interface PoliceConfig {
  purposes: readonly string[];
  piiPurposes: readonly string[];
  /** True while either list is the spec's default (GCAA has not decided). */
  pendingGcaa: boolean;
}

export type PoliceConfigResult = { config: PoliceConfig } | { problem: string };

function list(env: Record<string, string | undefined>, name: string, fallback: readonly string[]): { codes: readonly string[]; defaulted: boolean } | string {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return { codes: fallback, defaulted: true };
  const codes = raw.split(",").map((c) => c.trim());
  for (const c of codes) {
    if (!CODE.test(c)) return `${name}: ${JSON.stringify(c)} is not a purpose code ([a-z][a-z0-9_]{0,63})`;
  }
  if (new Set(codes).size !== codes.length) return `${name}: a purpose is repeated`;
  return { codes, defaulted: false };
}

export function policeConfigFromEnv(env: Record<string, string | undefined>): PoliceConfigResult {
  const purposes = list(env, "WEB_POLICE_PURPOSES", DEFAULT_POLICE_PURPOSES);
  if (typeof purposes === "string") return { problem: purposes };
  const pii = list(env, "WEB_POLICE_PII_PURPOSES", DEFAULT_POLICE_PII_PURPOSES);
  if (typeof pii === "string") return { problem: pii };
  const off = pii.codes.filter((c) => !purposes.codes.includes(c));
  if (off.length > 0) return { problem: `WEB_POLICE_PII_PURPOSES: ${off.join(", ")} not in WEB_POLICE_PURPOSES` };
  return { config: { purposes: purposes.codes, piiPurposes: pii.codes, pendingGcaa: purposes.defaulted || pii.defaulted } };
}

/** api's case reference bounds (PoliceQueryMeta case_ref: 1 to 100 characters). */
export const CASE_REF_MAX = 100;

/**
 * Why a query may not be sent, as a catalogue key, or null: a purpose
 * from the list and a case reference are required on every query (02
 * F10). The client's check; api makes the same one.
 */
export function queryBasisProblem(purpose: string, caseRef: string, allowed: readonly string[]): string | null {
  if (purpose === "" || !allowed.includes(purpose)) return "authority.police.basis.purpose_missing";
  const ref = caseRef.trim();
  if (ref === "") return "authority.police.basis.case_ref_missing";
  if (ref.length > CASE_REF_MAX) return "authority.police.basis.case_ref_long";
  return null;
}

/** "min_lon,min_lat,max_lon,max_lat" from four boxes, or null when one is not a number. */
export function bboxParam(minLng: string, minLat: string, maxLng: string, maxLat: string): string | null {
  const v = [minLng, minLat, maxLng, maxLat].map((s) => (s.trim() === "" ? Number.NaN : Number(s.trim())));
  if (v.some((n) => !Number.isFinite(n))) return null;
  return v.join(",");
}
