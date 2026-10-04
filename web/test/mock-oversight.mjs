// The stub api of WP-23's pages for test/mock-origin.mjs: violations,
// incidents and evidence packs, occurrence reports, sources, the audit
// log and the DPO report, the police realm, and the two public reads.
// The shapes are api/openapi.yaml's, and so are the refusals the pages
// meet: every operation admits only its x-roles in its x-realm (a police
// session is refused on every console operation, a console session on
// every police one: fail closed), a police query without a purpose or a
// case reference is 400 naming the field and records nothing, a review
// of a final violation is 409, broadcast evidence is not escalated
// without a note, the reporter is the incident officer's alone and needs
// a purpose, and the public check answers status only.
//
// Everything here is test data of this file, not anything's real data:
// GEO-TEST numbers and TEST serials (CLAUDE.md rule 11).
import { createHash } from "node:crypto";

const ULID_PREFIX = "01K6H3BV4H15G5E4G7X0NT";
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
let seq = 0;
/** A fresh ULID-shaped id: the pages' routes and api's patterns admit it. */
function ulid() {
  seq++;
  let tail = "";
  for (let n = seq, i = 0; i < 4; i++, n = Math.floor(n / 32)) tail = CROCKFORD[n % 32] + tail;
  return ULID_PREFIX + tail;
}

/** The purposes of the stub api (POLICE_PURPOSES and POLICE_PII_PURPOSES, the spec's defaults). */
const POLICE_PURPOSES = ["public_order", "traffic_enforcement", "criminal_investigation", "security_threat"];
const POLICE_PII_PURPOSES = ["criminal_investigation", "security_threat"];

const T0 = Date.parse("2026-10-03T12:00:00.000Z");
const iso = (ms) => new Date(ms).toISOString();

function sample(offsetS, lng) {
  return {
    msg_id: ulid(),
    captured_at: iso(T0 + offsetS * 1000),
    rx_ts: iso(T0 + offsetS * 1000 + 200),
    ts: iso(T0 + offsetS * 1000),
    time_source: "gnss",
    lat: 41.7,
    lng,
    alt_amsl_m: 712.4,
    alt_wgs84_m: null,
    alt_pressure_m: null,
    alt_source: "geodetic",
    speed_ms: 8.2,
    track_deg: 91,
    vspeed_ms: 0,
    status: "airborne",
    source: "direct_rid",
    source_instance: "rx-test-1",
    trust: "broadcast",
    identification: { status: "unknown_operator" },
  };
}

function violationWithHole() {
  const excerpt = [sample(0, 44.8), sample(1, 44.801), sample(2, 44.802), sample(11, 44.81), sample(12, 44.811)];
  return {
    violation_id: ulid(),
    kind: "height_120m",
    severity: "warning",
    track_id: "authority-1:rid:4A:7C:91:0E:22:B5",
    serial: "TESTSN0001",
    operator_reg: "GEOTEST00000001",
    zone_id: null,
    zone_type: null,
    detector_state: "updated",
    opened_at: iso(T0),
    closed_at: null,
    clear_reason: null,
    last_captured_at: iso(T0 + 12_000),
    policy_version: 4,
    peak: { name: "height_agl_m", value: 131.2 },
    in_uspace: false,
    evidence_trust: "broadcast",
    excerpt_samples: excerpt.length,
    cell5: "c5:1317:2248",
    status: "new",
    reviewed_at: null,
    alert_key: "height:authority-1:rid:4A:7C:91:0E:22:B5",
    registry_uas_id: null,
    zone_version: null,
    detail: { vertical_known: true, height_agl_m: 128.4, max_height_agl_m: 120, alt_hae_m: 731.9 },
    terrain_source: { dataset: "TEST-DEM-30", spacing_m: 30, attribution: "© TEST DEM fixture attribution" },
    evidence_refs: [{ type: "track", id: "authority-1:rid:4A:7C:91:0E:22:B5", version: null }],
    evidence_track_ids: ["authority-1:rid:4A:7C:91:0E:22:B5"],
    evidence_excerpt: excerpt,
    excerpt_truncated: false,
    reviewed_by: null,
    review_note: null,
    incident_requested: false,
    // As api cuts it (incidents.Cut with max_gap_s 3): 2 s -> 11 s is a hole.
    excerpt_segmenting: {
      state: "cut",
      max_gap_s: 3,
      policy_version: 4,
      writer_gaps_read: true,
      segments: [
        { from: iso(T0), to: iso(T0 + 2000), sample_indexes: [0, 1, 2] },
        { from: iso(T0 + 11_000), to: iso(T0 + 12_000), sample_indexes: [3, 4] },
      ],
      holes: [{ from: iso(T0 + 2000), to: iso(T0 + 11_000), duration_s: 9, causes: ["silence", "no recorded cause"], recorded: [] }],
      unplaced: [],
    },
  };
}

function violationContinuous() {
  const v = violationWithHole();
  const excerpt = [sample(0, 44.9), sample(1, 44.901), sample(2, 44.902)];
  return {
    ...v,
    violation_id: ulid(),
    kind: "zone_incursion",
    severity: "critical",
    track_id: "ussp-1:FL-2026-000417",
    serial: "TESTSN0002",
    zone_id: "GEO/TSTP001",
    zone_version: 2,
    zone_type: "PROHIBITED",
    peak: undefined,
    evidence_trust: "authenticated",
    detail: { vertical_known: true, identifier: "TSTP001" },
    terrain_source: null,
    evidence_excerpt: excerpt,
    excerpt_samples: excerpt.length,
    opened_at: iso(T0 - 60_000),
    excerpt_segmenting: {
      state: "cut",
      max_gap_s: 3,
      policy_version: 4,
      writer_gaps_read: true,
      segments: [{ from: iso(T0), to: iso(T0 + 2000), sample_indexes: [0, 1, 2] }],
      holes: [],
      unplaced: [],
    },
  };
}

const DETAIL_ONLY = ["alert_key", "registry_uas_id", "zone_version", "detail", "clearing_detail", "terrain_source", "evidence_refs", "evidence_track_ids", "evidence_excerpt", "excerpt_truncated", "reviewed_by", "review_note", "incident_requested", "excerpt_segmenting"];
const summaryOf = (v) => omit(v, DETAIL_ONLY);

function occurrence(within) {
  return {
    occurrence_id: ulid(),
    channel: "mandatory",
    origin: "client",
    category: "airprox",
    occurred_at: iso(T0 - 4 * 3600_000),
    became_aware_at: iso(T0 - 3 * 3600_000),
    received_at: within ? iso(T0 - 2 * 3600_000) : iso(T0 + 80 * 3600_000),
    reported_at: null,
    within_72h: within,
    report_deadline_s: 259_200,
    state: "received",
    risk_classification: null,
    classified_at: null,
    classified_by: null,
    has_reporter_person: true,
    aircraft: [{ serial: "TESTSN0003", operator_reg: "GEOTEST00000001" }],
    manned: [{ icao24: "4b1a2c", callsign: "TEST123" }],
    intent_refs: [],
    min_separation: { h_m: 140, v_m: 20, at: iso(T0 - 4 * 3600_000) },
    narrative: "A test narrative written by the reporter.",
    evidence_urls: [],
    analysis: "",
    follow_up: "",
    closed_at: null,
    updated_at: iso(T0 - 2 * 3600_000),
    updated_by: null,
  };
}

let st;
export function resetOversight() {
  seq = 0;
  const v1 = violationWithHole();
  const v2 = violationContinuous();
  const o1 = occurrence(true);
  const o2 = occurrence(false);
  st = {
    violations: [v1, v2],
    incidents: [],
    occurrences: [o1, o2],
    reporters: new Map([
      [o1.occurrence_id, { occurrence_id: o1.occurrence_id, reporter_org: "ussp-test-01", report_ref: "TEST-REP-1", person_ref: "TEST-PERSON-REF-7" }],
      [o2.occurrence_id, { occurrence_id: o2.occurrence_id, reporter_org: "ansp-01", report_ref: "TEST-REP-2", person_ref: null }],
    ]),
    controls: [{ source_type: "direct_rid", instance_id: "rx-test-2", enabled: false, reason: "test maintenance", actor: "admin:test.admin", changed_at: iso(T0 - 3600_000), version: 3 }],
    version: 3,
    policeQueries: [],
    exports: new Map(),
  };
}
resetOversight();

/** What the stub recorded of the police realm (tests only). */
export function oversightRecords() {
  return { policeQueries: st.policeQueries, exports: [...st.exports.keys()] };
}

// --- helpers -------------------------------------------------------------

function send(res, status, payload, headers = {}) {
  const text = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), "Cache-Control": "no-store", ...headers });
  res.end(text);
}

function problem(res, status, slug, detail, errors) {
  send(
    res,
    status,
    { type: `https://schemas.uspace.ge/problems/${slug}`, title: slug.replaceAll("_", " "), status, detail, ...(errors === undefined ? {} : { errors }) },
    { "Content-Type": "application/problem+json" },
  );
}

/** api's role and realm gate (x-roles, x-realm): true when it refused. */
function refused(res, s, roles, realm = "console") {
  if (s.realm !== realm) {
    problem(res, 403, "forbidden", `a ${s.realm} session is refused on this ${realm} operation`);
    return true;
  }
  if (!s.roles.some((r) => roles.includes(r))) {
    problem(res, 403, "forbidden", `this operation admits ${roles.join(", ")}`);
    return true;
  }
  return false;
}

const ID = "[0-7][0-9A-HJKMNP-TV-Z]{25}";

/** `o` without the members `keys` names. */
function omit(o, keys) {
  return Object.fromEntries(Object.entries(o).filter(([k]) => !keys.includes(k)));
}
const match = (p, re) => new RegExp(`^${re}$`).exec(p);

function zip(name) {
  const bytes = Buffer.from(`PK\u0003\u0004 test archive ${name}`);
  return { bytes, hash: `sha256:${createHash("sha256").update(bytes).digest("hex")}` };
}

function packOf(incident, kind, from, to, purpose, caseRef, actor) {
  const id = ulid();
  const { bytes, hash } = zip(id);
  return {
    pack_id: id,
    incident_id: incident.incident_id,
    kind,
    from,
    to,
    content_hash: hash,
    size_bytes: bytes.length,
    signature: null,
    signature_kid: "test-pub-1",
    seal_statement: { pack_id: id, incident_id: incident.incident_id, kind, content_hash: hash },
    manifest: {
      schema: "evidence-pack/v1",
      pack_id: id,
      kind,
      created_at: iso(Date.now()),
      redaction: kind === "legal" ? "legal: personal data resolved from the registry" : "oversight: no personal data",
      segmenting: { max_gap_s: 3, policy_version: 4 },
      sections: {
        tracks: { state: "included", basis: "observed", count: 1 },
        ussp_records: { state: "withheld", basis: "received", count: 0, reason: "an oversight pack fetches none" },
        manned_tracks: { state: "unavailable", basis: "received", count: 0, reason: "the ANSP feed cannot be read: test" },
      },
      tracks: [{ track_id: "authority-1:rid:4A:7C:91:0E:22:B5", file: "tracks/0001.json", samples: 5, segments: 2, holes: 1 }],
      agl_numbers: [{ violation_id: "x", name: "height_agl_m", value_m: 128.4, state: "observed", terrain_source: { dataset: "TEST-DEM-30", spacing_m: 30, attribution: "© TEST DEM fixture attribution" } }],
      inferred: [],
      files: [{ path: "manifest.json", sha256: "0".repeat(64), bytes: 10 }],
    },
    purpose,
    case_ref: caseRef,
    created_by: actor,
    created_at: iso(Date.now()),
    bytes,
  };
}

const packSummary = ({ pack_id, kind, from, to, content_hash, size_bytes, signature_kid, created_by, created_at }) => ({ pack_id, kind, from, to, content_hash, size_bytes, signature_kid, created_by, created_at });
const incidentView = (i) => ({ ...omit(i, ["packs"]), evidence_packs: i.packs.map(packSummary) });

function openIncident(input, actor) {
  const now = iso(Date.now());
  const inc = {
    incident_id: ulid(),
    kind: input.kind,
    occurred_at: input.occurred_at,
    opened_from: input.opened_from,
    source_violation_id: input.source_violation_id ?? null,
    notice_ref: input.notice_ref ?? null,
    intent_refs: [],
    narrative: input.narrative ?? "",
    severity: input.severity,
    status: "open",
    assignee: null,
    closed_at: null,
    opened_by: actor,
    created_at: now,
    updated_at: now,
    aircraft: [],
    notes: [],
    packs: [],
  };
  st.incidents.unshift(inc);
  return inc;
}

// --- the police realm ----------------------------------------------------

/** api's check of a police query's basis, before anything is read or recorded. */
function policeBasis(res, url, body) {
  const purpose = body?.purpose ?? url.searchParams.get("purpose");
  const caseRef = body?.case_ref ?? url.searchParams.get("case_ref");
  if (purpose === null || purpose === undefined || purpose === "") {
    problem(res, 400, "invalid_request", "purpose is required", [{ field: "purpose", reason: "required" }]);
    return null;
  }
  if (!POLICE_PURPOSES.includes(purpose)) {
    problem(res, 400, "invalid_request", "purpose is not on the list", [{ field: "purpose", reason: "not one of POLICE_PURPOSES" }]);
    return null;
  }
  if (caseRef === null || caseRef === undefined || String(caseRef).trim() === "" || String(caseRef).length > 100) {
    problem(res, 400, "invalid_request", "case_ref is required (1 to 100 characters)", [{ field: "case_ref", reason: "required" }]);
    return null;
  }
  return { purpose, case_ref: String(caseRef), pii: POLICE_PII_PURPOSES.includes(purpose) };
}

function recordPolice(s, kind, basis, query, results) {
  const id = ulid();
  st.policeQueries.push({ id, at: iso(Date.now()), user_id: s.sub, agency: "TEST-POLICE", kind, purpose: basis.purpose, case_ref: basis.case_ref, query, result_count: results, pii: basis.pii, remote_ip: "192.0.2.10" });
  return { query_id: id, purpose: basis.purpose, case_ref: basis.case_ref, pii_released: basis.pii };
}

const IDENTITY = { operator_id: "op-test-1", operator_type: "natural_person", full_name: "Test Operator One", postal_address: "1 Test Street, Testville", contact_email: "operator.one@example.test" };

async function police(req, res, url, s, body) {
  const p = url.pathname;
  if (refused(res, s, ["police.query"], "police")) return;
  if (p === "/v1/police/aircraft" && req.method === "GET") {
    const basis = policeBasis(res, url, null);
    if (basis === null) return;
    const bbox = (url.searchParams.get("bbox") ?? "").split(",").map(Number);
    if (bbox.length !== 4 || bbox.some((n) => !Number.isFinite(n))) return problem(res, 400, "invalid_request", "bbox", [{ field: "bbox", reason: "want min_lon,min_lat,max_lon,max_lat" }]);
    const now = Date.now();
    const aircraft = [
      {
        track_id: "authority-1:rid:4A:7C:91:0E:22:B5",
        serial: "TESTSN0001",
        registration_number: "GEOTEST00000001",
        identification_status: "registered",
        identification_reason: "matched",
        identification_basis: "as_broadcast",
        trust: "broadcast",
        source: "direct_rid",
        first_seen: iso(now - 20_000),
        last_seen: iso(now - 2000),
        emergency: false,
        positions: [{ at: iso(now - 2000), lat_deg: 41.71, lon_deg: 44.81, alt_amsl_m: 712.4, alt_source: "geodetic", height_m: 48, height_ref: "TakeoffLocation", speed_ms: 7.5, track_deg: 90 }],
        positions_truncated: false,
        ...(basis.pii ? { operator: IDENTITY } : {}),
      },
    ];
    const meta = recordPolice(s, "aircraft", basis, { bbox: url.searchParams.get("bbox") }, aircraft.length);
    return send(res, 200, {
      ...meta,
      mode: url.searchParams.has("at") ? "at" : "live",
      as_of: iso(now),
      window_from: iso(now - 30_000),
      window_to: iso(now),
      aircraft,
      truncated: false,
      sources: { newest_track_at: iso(now - 2000), newest_track_age_s: 2, writer_gaps: 0, writer_gap_causes: [], degraded: false },
    });
  }
  let m;
  if ((m = match(p, "/v1/police/operators/([^/]+)")) && req.method === "GET") {
    const basis = policeBasis(res, url, null);
    if (basis === null) return;
    const reg = decodeURIComponent(m[1]).split("-")[0];
    if (reg !== "GEOTEST00000001") {
      recordPolice(s, "operator", basis, { reg }, 0);
      return problem(res, 404, "not_found", "no such registration");
    }
    const meta = recordPolice(s, "operator", basis, { reg }, 1);
    return send(res, 200, {
      ...meta,
      operator: { registration_number: "GEOTEST00000001", operator_type: "natural_person", status: "active", valid_from: "2026-01-01T00:00:00Z", valid_until: "2027-01-01T00:00:00Z" },
      fleet: [{ serial: "TESTSN0001", status: "active", class_label: "C1", manufacturer: "TestMaker", model: "T-1" }],
      fleet_truncated: false,
      ...(basis.pii ? { identity: IDENTITY } : {}),
    });
  }
  if ((m = match(p, "/v1/police/serials/([^/]+)")) && req.method === "GET") {
    const basis = policeBasis(res, url, null);
    if (basis === null) return;
    const meta = recordPolice(s, "serial", basis, { serial: decodeURIComponent(m[1]) }, 1);
    return send(res, 200, {
      ...meta,
      uas: { serial: decodeURIComponent(m[1]), status: "active" },
      operator: { registration_number: "GEOTEST00000001", operator_type: "natural_person", status: "active", valid_from: "2026-01-01T00:00:00Z", valid_until: "2027-01-01T00:00:00Z" },
      ...(basis.pii ? { identity: IDENTITY } : {}),
    });
  }
  if (p === "/v1/police/exports" && req.method === "POST") {
    const basis = policeBasis(res, url, body);
    if (basis === null) return;
    if (!basis.pii) return problem(res, 403, "purpose_not_pii", "a legal pack needs a purpose of POLICE_PII_PURPOSES");
    const meta = recordPolice(s, "export", basis, body.query ?? { incident_id: body.incident_id }, 1);
    const inc = body.incident_id !== undefined ? st.incidents.find((i) => i.incident_id === body.incident_id) : openIncident({ kind: "other", occurred_at: body.from, opened_from: "police_request", severity: "info", notice_ref: `TEST-POLICE: ${basis.case_ref}` }, s.sub);
    if (inc === undefined) return problem(res, 404, "not_found", "no such incident");
    const pack = packOf(inc, "legal", body.from, body.to, basis.purpose, basis.case_ref, s.sub);
    st.exports.set(pack.pack_id, pack);
    return send(res, 201, {
      ...meta,
      pack_id: pack.pack_id,
      incident_id: inc.incident_id,
      incident_opened: body.incident_id === undefined,
      from: body.from,
      to: body.to,
      content_hash: pack.content_hash,
      size_bytes: pack.size_bytes,
      signature: null,
      signature_kid: pack.signature_kid,
      created_at: pack.created_at,
      download: `/v1/police/exports/${pack.pack_id}/download`,
    });
  }
  if ((m = match(p, `/v1/police/exports/(${ID})/download`)) && req.method === "GET") {
    const basis = policeBasis(res, url, null);
    if (basis === null) return;
    const pack = st.exports.get(m[1]);
    if (pack === undefined) return problem(res, 404, "not_found", "no export of this agency");
    recordPolice(s, "download", basis, { pack_id: m[1] }, 1);
    res.writeHead(200, { "Content-Type": "application/zip", "Content-Length": pack.bytes.length, "X-Content-SHA256": pack.content_hash, "X-Evidence-Signature": "" });
    return res.end(pack.bytes);
  }
  return problem(res, 404, "not_found", `${req.method} ${p}`);
}

// --- the console's operations ----------------------------------------------

/**
 * The public reads (no session). True when it answered.
 */
export function publicApi(req, res, url) {
  if (url.pathname === "/v1/registry/check" && req.method === "GET") {
    const n = (url.searchParams.get("number") ?? "").split("-")[0].toUpperCase();
    if (n === "") {
      problem(res, 400, "invalid_request", "number is required", [{ field: "number", reason: "required" }]);
      return true;
    }
    // Status only (api's RegistryCheck). The extra member is the test's
    // probe: a page that rendered what it was not given would show it.
    const status = n === "GEOTEST00000001" ? "valid" : n === "GEOTEST00000002" ? "suspended" : "unknown";
    send(res, 200, { status, ...(status === "unknown" ? {} : { valid_until: "2027-01-01T00:00:00Z" }), operator_name: "PROBE-NEVER-RENDERED" });
    return true;
  }
  if (url.pathname === "/v1/certificates/register" && req.method === "GET") {
    send(
      res,
      200,
      {
        generated_at: iso(Date.now()),
        certificates: [
          {
            certificate_id: "CERT-TEST-1",
            holder: "ussp",
            holder_name: "Test USSP Ltd",
            code: "USSPTST",
            services: ["network_identification", "flight_authorisation"],
            status: "operating",
            valid_from: "2026-01-01T00:00:00Z",
            valid_until: "2028-01-01T00:00:00Z",
            limitations: [],
          },
        ],
      },
      { "Cache-Control": "public, max-age=60" },
    );
    return true;
  }
  return false;
}

/**
 * WP-23's operations for a session `s`. Returns true when it answered,
 * false for a path it does not know (mock-origin answers 404).
 */
export async function oversightApi(req, res, url, s, body) {
  const p = url.pathname;
  const q = url.searchParams;
  let m;
  if (p.startsWith("/v1/police/")) {
    await police(req, res, url, s, body);
    return true;
  }
  // Violations (inspector).
  if (p === "/v1/violations" && req.method === "GET") {
    if (refused(res, s, ["inspector"])) return true;
    let list = st.violations;
    if (q.get("status")) list = list.filter((v) => v.status === q.get("status"));
    if (q.get("kind")) list = list.filter((v) => v.kind === q.get("kind"));
    send(res, 200, { violations: list.map(summaryOf) });
    return true;
  }
  if ((m = match(p, `/v1/violations/(${ID})`)) && req.method === "GET") {
    if (refused(res, s, ["inspector"])) return true;
    const v = st.violations.find((x) => x.violation_id === m[1]);
    if (v === undefined) problem(res, 404, "not_found", "no such violation");
    else send(res, 200, v);
    return true;
  }
  if ((m = match(p, `/v1/violations/(${ID})/review`)) && req.method === "POST") {
    if (refused(res, s, ["inspector"])) return true;
    const v = st.violations.find((x) => x.violation_id === m[1]);
    if (v === undefined) return problem(res, 404, "not_found", "no such violation"), true;
    if (v.status === "dismissed" || v.status === "escalated") return problem(res, 409, "violation_reviewed", `the violation is ${v.status}: final`), true;
    if (!["reviewed", "dismissed", "escalated"].includes(body.decision)) return problem(res, 400, "invalid_request", "decision", [{ field: "decision", reason: "unknown" }]), true;
    if (body.decision === "escalated" && v.evidence_trust === "broadcast" && (body.note ?? "").trim() === "") {
      return problem(res, 400, "invalid_request", "broadcast evidence is never escalated without a note", [{ field: "note", reason: "required for broadcast evidence" }]), true;
    }
    Object.assign(v, { status: body.decision, reviewed_at: iso(Date.now()), reviewed_by: s.sub, review_note: body.note ?? null });
    if (body.decision === "escalated") {
      v.incident_requested = true;
      openIncident({ kind: "violation_escalated", occurred_at: v.opened_at, opened_from: "violation", severity: v.severity, source_violation_id: v.violation_id }, s.sub);
    }
    send(res, 200, omit(v, ["excerpt_segmenting"]));
    return true;
  }
  // Incidents and evidence packs (inspector, incident_officer).
  const caseRoles = ["inspector", "incident_officer"];
  if (p === "/v1/incidents" && req.method === "GET") {
    if (refused(res, s, caseRoles)) return true;
    let list = st.incidents;
    if (q.get("violation_id")) list = list.filter((i) => i.source_violation_id === q.get("violation_id"));
    if (q.get("status")) list = list.filter((i) => i.status === q.get("status"));
    send(res, 200, { incidents: list.map((i) => omit(i, ["notes", "aircraft", "packs", "narrative", "intent_refs", "opened_by", "notice_ref"])) });
    return true;
  }
  if (p === "/v1/incidents" && req.method === "POST") {
    if (refused(res, s, caseRoles)) return true;
    if (!["own_observation", "ansp_notice", "ussp_notice"].includes(body.opened_from)) return problem(res, 400, "invalid_request", "opened_from", [{ field: "opened_from", reason: "not opened by hand" }]), true;
    send(res, 201, incidentView(openIncident(body, s.sub)));
    return true;
  }
  if ((m = match(p, `/v1/incidents/(${ID})`))) {
    if (refused(res, s, caseRoles)) return true;
    const inc = st.incidents.find((i) => i.incident_id === m[1]);
    if (inc === undefined) return problem(res, 404, "not_found", "no such incident"), true;
    if (req.method === "PATCH") {
      if (body.status === "assigned" && (body.assignee ?? inc.assignee) === null) return problem(res, 400, "invalid_request", "assignee", [{ field: "assignee", reason: "required to assign" }]), true;
      if (body.status !== undefined) inc.status = body.status;
      if (body.assignee !== undefined) inc.assignee = body.assignee;
      if (body.severity !== undefined) inc.severity = body.severity;
      if (body.note !== undefined) inc.notes.push({ id: inc.notes.length + 1, author: s.sub, body: body.note, created_at: iso(Date.now()) });
      for (const a of body.add_aircraft ?? []) inc.aircraft.push({ id: inc.aircraft.length + 1, serial: a.serial ?? null, operator_reg: a.operator_reg?.split("-")[0] ?? null, registry_uas_id: null, track_ids: a.track_ids ?? [], identification: {}, added_by: s.sub, added_at: iso(Date.now()) });
      inc.updated_at = iso(Date.now());
    }
    send(res, 200, incidentView(inc));
    return true;
  }
  if ((m = match(p, `/v1/incidents/(${ID})/evidence-packs`)) && req.method === "POST") {
    if (refused(res, s, caseRoles)) return true;
    const inc = st.incidents.find((i) => i.incident_id === m[1]);
    if (inc === undefined) return problem(res, 404, "not_found", "no such incident"), true;
    if ((body.purpose ?? "") === "") return problem(res, 400, "invalid_request", "purpose", [{ field: "purpose", reason: "required" }]), true;
    if (body.kind === "legal" && !s.roles.includes("inspector")) return problem(res, 403, "forbidden", "a legal pack needs a personal-data role"), true;
    const pack = packOf(inc, body.kind, body.from, body.to, body.purpose, body.case_ref ?? null, s.sub);
    inc.packs.push(pack);
    send(res, 201, omit(pack, ["bytes"]));
    return true;
  }
  if ((m = match(p, `/v1/incidents/(${ID})/evidence-packs/(${ID})(/download|/verify)?`)) && req.method === "GET") {
    if (refused(res, s, caseRoles)) return true;
    const pack = st.incidents.find((i) => i.incident_id === m[1])?.packs.find((x) => x.pack_id === m[2]);
    if (pack === undefined) return problem(res, 404, "not_found", "no such pack"), true;
    if (m[3] === "/download") {
      if ((q.get("purpose") ?? "") === "") return problem(res, 400, "invalid_request", "purpose", [{ field: "purpose", reason: "required" }]), true;
      res.writeHead(200, { "Content-Type": "application/zip", "Content-Length": pack.bytes.length, "X-Content-SHA256": pack.content_hash, "X-Evidence-Signature": "test.jws" });
      res.end(pack.bytes);
      return true;
    }
    if (m[3] === "/verify") {
      send(res, 200, { pack_id: pack.pack_id, content_hash: pack.content_hash, recomputed_hash: pack.content_hash, hash_matches: true, problem: null, signature: "verified", signature_detail: null, verified_at: iso(Date.now()) });
      return true;
    }
    send(res, 200, omit(pack, ["bytes"]));
    return true;
  }
  // Occurrence reports (list and read: incident_officer, inspector; the rest: incident_officer).
  if (p === "/v1/occurrences" && req.method === "GET") {
    if (refused(res, s, ["incident_officer", "inspector"])) return true;
    const detailOnly = ["aircraft", "manned", "intent_refs", "min_separation", "narrative", "evidence_urls", "analysis", "follow_up", "report_deadline_s", "classified_at", "classified_by", "updated_by"];
    send(res, 200, { occurrences: st.occurrences.map((o) => omit(o, detailOnly)) });
    return true;
  }
  if (p === "/v1/occurrences/export" && req.method === "POST") {
    if (refused(res, s, ["incident_officer"])) return true;
    const content = JSON.stringify({ format: "eccairs-compatible-draft", records: st.occurrences.map((o) => ({ category: o.category, narrative: o.narrative })) });
    send(res, 201, { export_id: ulid(), format: "eccairs-compatible-draft", created_at: iso(Date.now()), record_count: st.occurrences.length, size_bytes: content.length, content_hash: `sha256:${createHash("sha256").update(content).digest("hex")}`, content });
    return true;
  }
  if ((m = match(p, `/v1/occurrences/(${ID})(/reporter|/classify|/analysis)?`))) {
    const o = st.occurrences.find((x) => x.occurrence_id === m[1]);
    if (m[2] === undefined && req.method === "GET") {
      if (refused(res, s, ["incident_officer", "inspector"])) return true;
    } else if (refused(res, s, ["incident_officer"])) return true;
    if (o === undefined) return problem(res, 404, "not_found", "no such report"), true;
    if (m[2] === "/reporter" && req.method === "GET") {
      if ((q.get("purpose") ?? "") === "") return problem(res, 400, "invalid_request", "purpose", [{ field: "purpose", reason: "required" }]), true;
      send(res, 200, st.reporters.get(o.occurrence_id));
      return true;
    }
    if (m[2] === "/classify" && req.method === "POST") {
      if (o.state === "closed") return problem(res, 409, "occurrence_closed", "closed"), true;
      Object.assign(o, { risk_classification: body.risk_classification, state: o.state === "received" ? "classified" : o.state, updated_at: iso(Date.now()) });
    } else if (m[2] === "/analysis" && req.method === "PATCH") {
      if (o.state === "received") return problem(res, 409, "occurrence_not_classified", "classify it first"), true;
      Object.assign(o, { analysis: body.analysis ?? o.analysis, follow_up: body.follow_up ?? o.follow_up, ...(body.state === undefined ? {} : { state: body.state }), updated_at: iso(Date.now()) });
    }
    send(res, 200, o);
    return true;
  }
  // Sources (admin).
  if (p === "/v1/sources" && req.method === "GET") {
    if (refused(res, s, ["admin"])) return true;
    const off = (t, i) => st.controls.find((c) => c.source_type === t && c.instance_id === i && !c.enabled);
    const typeOff = (t) => st.controls.find((c) => c.source_type === t && c.instance_id === undefined && !c.enabled);
    const view = (t, i, health, extra = {}) => {
      const byType = typeOff(t);
      const byInst = off(t, i);
      const d = byType ?? byInst;
      return {
        source_type: t,
        instance_id: i,
        switch: d === undefined ? "enabled" : "disabled",
        ...(d === undefined ? {} : { disabled_by: byType !== undefined ? "type" : "instance", disabled_by_who: d.actor, disabled_reason: d.reason }),
        health,
        counters: { accepted: 120, refused_disabled: 0 },
        ...extra,
      };
    };
    send(res, 200, {
      epoch: "test-epoch",
      version: st.version,
      default_deny: false,
      controls: st.controls,
      sources: [view("direct_rid", "rx-test-1", "healthy", { age_s: 1.2, status_age_s: 2 }), view("direct_rid", "rx-test-2", "stale", { age_s: 400, status_age_s: 3 }), view("network_rid", "ussp-test", "lagging", { age_s: 1, lag_s: 12, status_age_s: 2 }), view("ansp_feed", "ansp-1", "never_heard")],
    });
    return true;
  }
  if ((m = match(p, "/v1/sources/(direct_rid|network_rid|ansp_feed)(?:/([A-Za-z0-9][A-Za-z0-9_-]{0,62}))?")) && req.method === "PUT") {
    if (refused(res, s, ["admin"])) return true;
    if (typeof body.reason !== "string" || body.reason.trim() === "") return problem(res, 400, "invalid_request", "reason", [{ field: "reason", reason: "required" }]), true;
    const t = m[1];
    const i = m[2];
    const existing = st.controls.find((c) => c.source_type === t && c.instance_id === i);
    if (existing !== undefined && existing.enabled === body.enabled) return send(res, 200, { control: existing, changed: false, epoch: "test-epoch", version: st.version }), true;
    st.version++;
    const control = { source_type: t, ...(i === undefined ? {} : { instance_id: i }), enabled: body.enabled, reason: body.reason, actor: `admin:${s.username}`, changed_at: iso(Date.now()), version: st.version };
    st.controls = [...st.controls.filter((c) => !(c.source_type === t && c.instance_id === i)), control];
    send(res, 200, { control, changed: true, epoch: "test-epoch", version: st.version });
    return true;
  }
  // The audit log and the DPO report (admin, auditor).
  if (p === "/v1/audit/events" && req.method === "GET") {
    if (refused(res, s, ["admin", "auditor"])) return true;
    const h = (n) => createHash("sha256").update(String(n)).digest("hex");
    send(res, 200, {
      events: [
        { id: 12, ts: iso(T0), actor_type: "user", actor_id: "user-inspector1", realm: "console", entity_type: "violation", entity_id: st.violations[0].violation_id, event_type: "violation_reviewed", payload: {}, prev_hash: h(11), hash: h(12) },
        { id: 11, ts: iso(T0 - 1000), actor_type: "system", actor_id: "detect", entity_type: "violation", entity_id: st.violations[0].violation_id, event_type: "violation_raised", payload: {}, prev_hash: h(10), hash: h(11) },
      ],
    });
    return true;
  }
  if (p === "/v1/audit/verify" && req.method === "GET") {
    if (refused(res, s, ["admin", "auditor"])) return true;
    const month = q.get("month") ?? "";
    if (!/^[0-9]{4}-(0[1-9]|1[0-2])$/.test(month)) return problem(res, 400, "invalid_request", "month", [{ field: "month", reason: "want YYYY-MM" }]), true;
    // 2026-09 holds no row; any other month is intact.
    if (month === "2026-09") return send(res, 200, { month, rows: 0, intact: true, verified_at: iso(Date.now()) }), true;
    send(res, 200, { month, rows: 2, first_id: 11, last_id: 12, last_hash: "f".repeat(64), intact: true, verified_at: iso(Date.now()) });
    return true;
  }
  if (p === "/v1/audit/dpo-report" && req.method === "GET") {
    if (refused(res, s, ["admin", "auditor"])) return true;
    const month = q.get("month") ?? "";
    send(res, 200, {
      month,
      from: `${month}-01T00:00:00Z`,
      to: iso(Date.now()),
      police_queries: st.policeQueries,
      pii_views: [],
      truncated: false,
      totals: { police_queries: st.policeQueries.length, police_queries_with_pii: st.policeQueries.filter((x) => x.pii).length, pii_views: 0 },
    });
    return true;
  }
  return false;
}
