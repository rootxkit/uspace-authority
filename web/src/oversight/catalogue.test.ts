// Every value an enumeration of WP-23's pages can show has its words in
// both languages: a key built from a value (`authority.x.${value}`) is
// invisible to the literal-key check of src/i18n/catalogue.test.ts.
import { describe, expect, it } from "vitest";
import { en, ka } from "../i18n/catalogues";
import {
  ANALYSIS_STATES,
  INCIDENT_KINDS,
  INCIDENT_OPENED_FROM,
  INCIDENT_STATUSES,
  OCCURRENCE_CATEGORIES,
  OCCURRENCE_CHANNELS,
  OCCURRENCE_STATES,
  PACK_KINDS,
  REVIEW_DECISIONS,
  SOURCE_TYPES,
  VIOLATION_KINDS,
  VIOLATION_STATUSES,
} from "./enums";

const families: [string, readonly string[]][] = [
  ["authority.violation.kind", VIOLATION_KINDS],
  ["authority.violation.status", VIOLATION_STATUSES],
  ["authority.violation.decision", REVIEW_DECISIONS],
  ["authority.violation.clear", ["resolved", "stale", "landed", "source_disabled", "flight_ended", "reconfigured", "authorised", "detector_silent", "unknown"]],
  ["authority.incident.kind", INCIDENT_KINDS],
  ["authority.incident.status", INCIDENT_STATUSES],
  ["authority.incident.opened_from", INCIDENT_OPENED_FROM],
  ["authority.pack.kind", PACK_KINDS],
  ["authority.pack.signature", ["verified", "invalid", "unsigned", "unverifiable"]],
  ["authority.occurrence.state", [...OCCURRENCE_STATES, ...ANALYSIS_STATES]],
  ["authority.occurrence.category", OCCURRENCE_CATEGORIES],
  ["authority.occurrence.channel", OCCURRENCE_CHANNELS],
  ["authority.occurrence.origin", ["client", "operator"]],
  ["authority.source_type", SOURCE_TYPES],
  ["authority.sources.health", ["healthy", "stale", "lagging", "never_heard"]],
  ["authority.sources.disabled", ["type", "instance", "default_deny"]],
  ["authority.hole", ["silence", "no_recorded_cause", "writer_gap", "sample_without_position", "frame_undecodable", "writer_gaps_unread"]],
  ["authority.police.unresolved", ["not_identified", "not_in_registry", "ambiguous_registration", "registry_unavailable"]],
  ["authority.registry_status", ["active", "suspended", "revoked", "expired"]],
  ["authority.public.check.status", ["valid", "suspended", "revoked", "unknown"]],
  ["authority.public.register.holder", ["ussp", "cisp"]],
  ["authority.public.register.state", ["issued", "operating", "ceased", "suspended", "limited", "revoked", "lapsed"]],
  [
    "authority.public.register.service",
    ["network_identification", "geo_awareness", "flight_authorisation", "traffic_information", "weather", "conformance_monitoring", "common_information"],
  ],
];

describe("WP-23 catalogue families", () => {
  for (const [prefix, values] of families) {
    it(`${prefix}.* has every value in ka and en`, () => {
      const missing = values.flatMap((v) => [`${prefix}.${v}`].filter((k) => !(k in en) || !(k in ka)));
      expect(missing).toEqual([]);
    });
  }

  it("a value without words is found (the pair above)", () => {
    expect("authority.violation.kind.not_a_kind" in en).toBe(false);
  });
});
