// The enumerations WP-23's filters and forms offer, as runtime lists. Each
// is checked against the generated API type in both directions, so a
// value api adds or drops fails the type check instead of going missing
// from a filter (the types stay generated, never written: spec 00 §6.2).
import type { components } from "../api/types";

type S = components["schemas"];

/** True when `L` names every member of `U` (and, by the `satisfies`, nothing else). */
type Covers<U extends string, L extends readonly string[]> = [Exclude<U, L[number]>] extends [never] ? true : false;

function exact<U extends string>() {
  return <const L extends readonly U[]>(l: L & (Covers<U, L> extends true ? unknown : never)): L => l;
}

export const VIOLATION_KINDS = exact<S["ViolationKind"]>()([
  "height_120m",
  "zone_incursion",
  "unregistered",
  "no_authorisation",
  "identification_mismatch",
  "rid_absent",
]);
export const VIOLATION_STATUSES = exact<S["ViolationStatus"]>()(["new", "reviewed", "dismissed", "escalated"]);
export const REVIEW_DECISIONS = exact<S["ViolationReviewInput"]["decision"]>()(["reviewed", "dismissed", "escalated"]);

export const INCIDENT_KINDS = exact<S["IncidentKind"]>()(["airprox", "nonconformance", "lost_link", "emergency", "violation_escalated", "other"]);
export const INCIDENT_STATUSES = exact<S["IncidentStatus"]>()(["open", "assigned", "closed"]);
export const INCIDENT_SEVERITIES = exact<S["IncidentSeverity"]>()(["info", "warning", "critical"]);
/** What a person may open an incident from here; violation and police_request are api's own (refused by hand). */
export const INCIDENT_OPENED_BY_HAND = ["own_observation", "ansp_notice", "ussp_notice"] as const satisfies readonly S["IncidentOpenedFrom"][];
export const INCIDENT_OPENED_FROM = exact<S["IncidentOpenedFrom"]>()(["violation", "own_observation", "ansp_notice", "ussp_notice", "police_request"]);
export const PACK_KINDS = exact<S["EvidencePackKind"]>()(["oversight", "legal"]);

export const OCCURRENCE_STATES = exact<S["OccurrenceState"]>()(["received", "classified", "analysed", "closed"]);
export const OCCURRENCE_CATEGORIES = exact<S["OccurrenceCategory"]>()([
  "airprox",
  "nonconformance_in_prohibited",
  "lost_link_in_uspace",
  "emergency",
  "other",
]);
export const OCCURRENCE_CHANNELS = exact<S["OccurrenceChannel"]>()(["mandatory", "voluntary"]);
export const ANALYSIS_STATES = exact<NonNullable<S["OccurrenceAnalysisPatch"]["state"]>>()(["analysed", "closed"]);

export const SOURCE_TYPES = exact<S["SourceType"]>()(["direct_rid", "network_rid", "ansp_feed"]);
