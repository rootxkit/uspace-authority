// The stub api of the WP-22 pages, for test/mock-origin.mjs: the
// registry, zones and U-space airspaces, publications and certificates,
// in the shapes of api/openapi.yaml, kept in memory. Each operation
// answers only the roles of its x-roles (403 otherwise), validates what
// the real api refuses that the tests exercise (a missing purpose, a
// zone without its identifier, an invalid import), and records every
// request with its body so a test can read what the console sent.
//
// The CISP is a fake too: a publication is `pending` with its age until
// POST /__mock/authoring/cisp {"ack": true} acknowledges every pending
// one (what WP-6's sender does when the CISP answers 201).
//
// Control (tests only), under /__mock/authoring/:
//   GET  requests                    every request: method, path, query, body
//   POST cisp {ack?: true}            acknowledge the pending publications
//   POST state {applications?: "on"|"off"}
//
// Everything here is test data of this file: GEO-TEST numbers, TEST
// serials, synthetic names.
import { randomBytes } from "node:crypto";

export const AUTHORING_ACCOUNTS = {
  viewer1: { password: "viewer1-test-password", roles: ["viewer"] },
  admin1: { password: "admin1-test-password", roles: ["admin"] },
};

const iso = (ms) => new Date(ms).toISOString();

function json(res, status, payload, headers = {}) {
  const text = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), "Cache-Control": "no-store", ...headers });
  res.end(text);
}

function problem(res, status, slug, title, detail, errors = []) {
  const text = JSON.stringify({ type: `https://schemas.uspace.ge/problems/${slug}`, title, status, detail, errors });
  res.writeHead(status, { "Content-Type": "application/problem+json", "Content-Length": Buffer.byteLength(text) });
  res.end(text);
}

const has = (s, roles) => s.roles.some((r) => roles.includes(r));
const id16 = () => randomBytes(8).toString("hex");

function seed(zonesSeed) {
  const op = {
    id: "op-1",
    operator_type: "natural",
    registration_number: "GEOTEST00000001",
    has_secret_part: true,
    competency_confirmation: false,
    authorisations: [],
    status: "active",
    status_reason: "",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2027-01-01T00:00:00Z",
    source: "manual",
    registry_version: 3,
    created_at: "2026-01-01T00:00:00Z",
    created_by: "user-registrar1",
    updated_at: "2026-01-01T00:00:00Z",
    updated_by: "user-registrar1",
  };
  const uas = {
    id: "uas-1",
    operator_id: "op-1",
    serial: "TESTSERIAL0001",
    manufacturer_code: "TEST",
    manufacturer: "Test Aircraft",
    model: "T-1",
    class_label: "C1",
    mtom_g: 900,
    rid_capability: "direct",
    status: "active",
    status_reason: "",
    registered_at: "2026-01-02T00:00:00Z",
    registry_version: 3,
    created_by: "user-registrar1",
    updated_at: "2026-01-02T00:00:00Z",
    updated_by: "user-registrar1",
  };
  const pilot = {
    id: "pil-1",
    operator_id: "op-1",
    status: "active",
    status_reason: "",
    competencies: [{ competency: "A1_A3", certificate_ref: "TEST-CERT-1", valid_until: "2028-01-01T00:00:00Z", recorded_at: "2026-01-03T00:00:00Z", recorded_by: "user-registrar1" }],
    registry_version: 3,
    created_at: "2026-01-03T00:00:00Z",
    created_by: "user-registrar1",
    updated_at: "2026-01-03T00:00:00Z",
    updated_by: "user-registrar1",
  };
  const zones = new Map();
  for (const z of zonesSeed) zones.set(z.identifier, [{ ...z }]);
  const cert = {
    id: "0123456789abcdef0123456789abcdef",
    holder: "ussp",
    holder_name: "Test USSP",
    holder_address: "1 Test Street",
    holder_email: "ops@ussp.test",
    holder_phone: "+995000000001",
    holder_url: "https://ussp.test",
    code: "TESTU1",
    client_id: "ussp-TESTU1-01",
    base_url: "https://ussp.test/api",
    services: ["network_identification", "traffic_information"],
    conditions: "",
    limitations: [],
    terms_url: "https://ussp.test/terms",
    issued_at: "2026-02-01T00:00:00Z",
    valid_until: "2028-02-01T00:00:00Z",
    status: "operating",
    operations: "operating",
    operations_started_at: "2026-02-10T00:00:00Z",
    limited: false,
    suspended: false,
    status_reason: "",
    status_changed_at: "2026-02-10T00:00:00Z",
    status_changed_by: "client:ussp-TESTU1-01",
    lapse_unused_after_months: 6,
    lapse_ceased_after_months: 12,
    created_at: "2026-02-01T00:00:00Z",
    created_by: "user-admin1",
    updated_at: "2026-02-10T00:00:00Z",
    updated_by: "user-admin1",
  };
  return {
    operators: new Map([[op.id, op]]),
    pii: new Map([[op.id, { operator_id: op.id, full_name: "Test Person", date_of_birth: "1990-01-01", postal_address: "1 Test Street, Tbilisi", contact_email: "person@example.test", contact_phone: "+995000000002" }]]),
    uas: new Map([[uas.id, uas]]),
    pilots: new Map([[pilot.id, pilot]]),
    pilotPii: new Map([[pilot.id, { pilot_id: pilot.id, name: "Test Pilot", person_ref_last4: "1234" }]]),
    applications: [
      { application_id: "app-1", kind: "operator_registration", state: "submitted", operator_type: "legal", lang: "ka", submitted_at: "2026-10-01T09:00:00Z", verified_at: "2026-10-01T09:05:00Z" },
    ],
    applicationsOn: true,
    zones,
    zonesVersion: 7,
    publications: [],
    certs: new Map([[cert.id, cert]]),
    notices: new Map([[cert.id, [{ id: 1, state: "started", at: "2026-02-10T00:00:00Z", reference: "TEST-START-1", source: "machine", recorded_by: "client:ussp-TESTU1-01", received_at: "2026-02-10T00:00:05Z" }]]]),
    seq: 10,
  };
}

const featureOf = (z) => z.feature ?? {};
const newest = (vs) => vs[vs.length - 1];

function versionOut(z) {
  return z;
}

/** The authoring stub: `handle` answers a request it owns and returns true. */
export function createAuthoring({ zonesSeed }) {
  let st = seed(zonesSeed);
  const requests = [];

  function reset() {
    st = seed(zonesSeed);
    requests.length = 0;
  }

  function publicationRow(dataset, n, by) {
    const row = {
      id: ++st.seq,
      dataset,
      version: dataset === "ussp_list" ? st.seq : ++st.zonesVersion,
      payload_hash: randomBytes(32).toString("hex"),
      feature_count: n,
      content_type: "application/geo+json",
      state: "pending",
      attempts: 0,
      signature_kid: null,
      signed_at: null,
      next_retry_at: null,
      cisp_version: null,
      conflict_version: null,
      last_attempt_at: null,
      last_status: null,
      last_error: null,
      acknowledged_at: null,
      created_at: iso(Date.now()),
      created_by: by,
      state_changed_at: iso(Date.now()),
    };
    st.publications.unshift(row);
    return row;
  }

  function publicationsOut(dataset, limit) {
    const now = Date.now();
    const rows = st.publications
      .filter((r) => dataset === undefined || r.dataset === dataset)
      .slice(0, limit)
      .map((r) => ({ ...r, age_s: r.state === "pending" || r.state === "sent" ? (now - Date.parse(r.created_at)) / 1000 : null }));
    return {
      cisp_configured: true,
      publications: rows,
      cache: [],
      heartbeat: { enabled: true, interval_s: 15, last_success_at: iso(now), last_status: 204, last_error: null, consecutive_failures: 0 },
      subscription: { enabled: false },
    };
  }

  function listZones(ds, state) {
    const out = [];
    for (const vs of st.zones.values()) for (const v of vs) if (v.dataset === ds && (state === null || v.state === state)) out.push(versionOut(v));
    return out.sort((a, b) => a.identifier.localeCompare(b.identifier) || a.zone_version - b.zone_version);
  }

  /** The draft of a body, or the field errors the real api would answer. */
  function draftOf(ds, body, pathId, s) {
    const f = body?.feature;
    const p = f?.properties ?? {};
    const errors = [];
    const fromK = ds === "zones" ? "valid_from" : "designated_from";
    const toK = ds === "zones" ? "valid_to" : "designated_to";
    if (typeof p.identifier !== "string" || p.identifier === "" || p.identifier.length > 7) errors.push({ field: "feature.properties.identifier", reason: "required, at most 7 characters" });
    if (typeof p.type !== "string") errors.push({ field: "feature.properties.type", reason: "required" });
    if (!Array.isArray(p.zoneAuthority) || p.zoneAuthority.length === 0) errors.push({ field: "feature.properties.zoneAuthority", reason: "a zone without an authority" });
    if (typeof body?.[fromK] !== "string") errors.push({ field: fromK, reason: "required" });
    if (typeof body?.[toK] !== "string") errors.push({ field: toK, reason: "required" });
    if (ds === "uspace_airspace" && typeof body?.designation !== "object") errors.push({ field: "designation", reason: "required" });
    if (pathId !== null && p.identifier !== pathId) errors.push({ field: "feature.properties.identifier", reason: `${JSON.stringify(p.identifier)} is not the path's identifier ${JSON.stringify(pathId)}` });
    if (errors.length > 0) return { errors };
    const vs = st.zones.get(p.identifier) ?? [];
    for (const v of vs) if (v.state === "draft" || v.state === "approved") v.state = "superseded";
    const ext = (f.geometry?.layer?.lowerReference === "WGS84" || f.geometry?.layer?.upperReference === "WGS84") ? [{ field: "feature.geometry.layer", reason: "WGS84 is this project's extension of ED-318" }] : [];
    const v = {
      dataset: ds,
      identifier: p.identifier,
      zone_version: vs.length === 0 ? 1 : newest(vs).zone_version + 1,
      state: "draft",
      type: p.type,
      country: p.country ?? "",
      feature: f,
      valid_from: body[fromK],
      valid_to: body[toK],
      extensions: ext,
      ...(ds === "uspace_airspace" ? { designation: body.designation } : {}),
      created_at: iso(Date.now()),
      created_by: s.sub,
    };
    vs.push(v);
    st.zones.set(p.identifier, vs);
    return { version: v };
  }

  function importZones(raw, query, s) {
    let doc;
    try {
      doc = JSON.parse(raw.replace(/^﻿/, ""));
    } catch {
      return { errors: [{ field: "$", reason: "not JSON" }] };
    }
    const features = Array.isArray(doc?.features) ? doc.features : Array.isArray(doc?.UASZoneList) ? doc.UASZoneList : null;
    if (features === null) return { errors: [{ field: "$", reason: "neither ED-318 nor ED-269" }] };
    const format = typeof doc.type === "string" ? "ed318" : "ed269";
    const errors = [];
    features.forEach((ft, i) => {
      const p = format === "ed318" ? ft?.properties : ft;
      if (typeof p?.identifier !== "string") errors.push({ field: `features[${i}].properties.identifier`, reason: "required" });
      if (format === "ed318" && typeof p?.type !== "string") errors.push({ field: `features[${i}].properties.type`, reason: "required" });
      if (format === "ed269" && p?.restriction === "REQ_AUTHORIZATION") errors.push({ field: `features[${i}].restriction`, reason: "'REQ_AUTHORIZATION' is the ED-318 spelling; ED-269 spells it REQ_AUTHORISATION" });
    });
    const from = query.get("valid_from") ?? doc.metadata?.validFrom;
    const to = query.get("valid_to") ?? doc.metadata?.validTo;
    if (from === undefined) errors.push({ field: "valid_from", reason: "required: the request's or the collection's metadata.validFrom" });
    if (to === undefined) errors.push({ field: "valid_to", reason: "required: the request's or the collection's metadata.validTo" });
    if (errors.length > 0) return { errors };
    const created = [];
    for (const ft of features) {
      const r = draftOf("zones", { feature: ft, valid_from: from, valid_to: to }, null, s);
      if (r.version !== undefined) created.push(r.version);
    }
    return { result: { format, created } };
  }

  function certChange(c, s, list = "queued") {
    c.updated_at = iso(Date.now());
    c.updated_by = s.sub;
    c.status = c.ended_at !== undefined ? c.status : c.suspended ? "suspended" : c.operations === "ceased" ? "ceased" : c.limited ? "limited" : c.operations === "operating" ? "operating" : "issued";
    const pub = list === "queued" ? publicationRow("ussp_list", 1, s.sub) : null;
    return { certificate: c, client_status: c.status === "revoked" ? "revoked" : c.suspended ? "suspended" : "active", list_publication: pub === null ? { state: "not_needed" } : { state: "queued", publication_id: pub.id } };
  }

  /** Answers the request when it is one of these pages' operations. */
  function handle(req, res, url, s, body, raw) {
    const p = url.pathname;
    const m = req.method;
    const q = url.searchParams;
    if (!/^\/v1\/(registry|zones|uspace|publications|certificates)(\/|$)/.test(p)) return false;
    requests.push({ method: m, path: p, query: Object.fromEntries(q.entries()), body });
    const R = (roles) => {
      if (has(s, roles)) return true;
      problem(res, 403, "forbidden", "Forbidden", `${m} ${p} is not this role's`);
      return false;
    };
    let g;

    // --- registry -------------------------------------------------------
    if (p === "/v1/registry/operators" && m === "GET") {
      if (!R(["registrar", "inspector", "viewer"])) return true;
      const n = (q.get("number") ?? "").toUpperCase();
      const rows = [...st.operators.values()].filter((o) => (n === "" || o.registration_number.toUpperCase() === n) && (q.get("status") === null || o.status === q.get("status")));
      return json(res, 200, { operators: rows }), true;
    }
    if (p === "/v1/registry/operators" && m === "POST") {
      if (!R(["registrar"])) return true;
      const errors = ["operator_type", "registration_number", "postal_address", "contact_email", "contact_phone", "valid_until"].filter((f) => typeof body?.[f] !== "string" || body[f] === "").map((f) => ({ field: f, reason: "required" }));
      if (typeof body?.registration_number === "string" && body.registration_number.includes("-")) errors.push({ field: "registration_number", reason: "the public part only; a number with a hyphen is refused" });
      if (errors.length > 0) return problem(res, 400, "validation", "Invalid request", "", errors), true;
      if ([...st.operators.values()].some((o) => o.registration_number === body.registration_number)) return problem(res, 409, "conflict", "Registered already", "", [{ field: "registration_number", reason: "registered already" }]), true;
      const now = iso(Date.now());
      const o = { id: `op-${++st.seq}`, operator_type: body.operator_type, registration_number: body.registration_number, has_secret_part: typeof body.secret_part === "string", competency_confirmation: body.competency_confirmation === true, authorisations: body.authorisations ?? [], status: "active", status_reason: "", valid_from: body.valid_from ?? now, valid_until: body.valid_until, source: body.source ?? "manual", registry_version: ++st.seq, created_at: now, created_by: s.sub, updated_at: now, updated_by: s.sub };
      st.operators.set(o.id, o);
      st.pii.set(o.id, { operator_id: o.id, full_name: body.full_name, legal_name: body.legal_name, date_of_birth: body.date_of_birth, legal_identification_number: body.legal_identification_number, postal_address: body.postal_address, contact_email: body.contact_email, contact_phone: body.contact_phone, insurance_policy_number: body.insurance_policy_number });
      return json(res, 201, o), true;
    }
    if ((g = /^\/v1\/registry\/(operators|uas|pilots)\/([^/]+)(\/(status|personal-data|competencies))?$/.exec(p))) {
      const [, kind, id, , sub] = g;
      const store = kind === "operators" ? st.operators : kind === "uas" ? st.uas : st.pilots;
      const row = store.get(id);
      if (sub === undefined && m === "GET") {
        if (!R(["registrar", "inspector", "viewer"])) return true;
        return row === undefined ? (problem(res, 404, "not_found", "Not found", id), true) : (json(res, 200, row), true);
      }
      if (row === undefined) return problem(res, 404, "not_found", "Not found", id), true;
      if (sub === undefined && m === "PATCH") {
        if (!R(["registrar"])) return true;
        Object.assign(row, Object.fromEntries(Object.entries(body ?? {}).filter(([k]) => k in row || ["registration_mark", "owner_ref", "class_label", "mtom_g", "operator_id", "authorisations", "competency_confirmation", "valid_until"].includes(k))));
        row.updated_at = iso(Date.now());
        row.updated_by = s.sub;
        return json(res, 200, row), true;
      }
      if (sub === "status" && m === "POST") {
        if (!R(["registrar"])) return true;
        if (!["active", "suspended", "revoked"].includes(body?.status)) return problem(res, 400, "validation", "Invalid request", "", [{ field: "status", reason: "active, suspended or revoked" }]), true;
        if (body.status !== "active" && (typeof body.reason !== "string" || body.reason.trim() === "")) return problem(res, 400, "validation", "Invalid request", "", [{ field: "reason", reason: "required for suspended and revoked" }]), true;
        row.status = body.status;
        row.status_reason = body.reason ?? "";
        row.registry_version = ++st.seq;
        return json(res, 200, row), true;
      }
      if (sub === "personal-data" && m === "GET" && kind !== "uas") {
        if (!R(["registrar", "inspector"])) return true;
        const purpose = q.get("purpose");
        if (purpose === null || purpose.trim() === "") return problem(res, 400, "validation", "Invalid request", "a personal data read needs its purpose", [{ field: "purpose", reason: "required" }]), true;
        return json(res, 200, (kind === "operators" ? st.pii : st.pilotPii).get(id), { "Cache-Control": "no-store" }), true;
      }
      if (sub === "competencies" && m === "POST" && kind === "pilots") {
        if (!R(["registrar"])) return true;
        row.competencies.push({ ...body, recorded_at: iso(Date.now()), recorded_by: s.sub });
        return json(res, 200, row), true;
      }
    }
    if (p === "/v1/registry/uas" && m === "GET") {
      if (!R(["registrar", "inspector", "viewer"])) return true;
      const serial = q.get("serial");
      const rows = [...st.uas.values()].filter((u) => (serial === null || u.serial === serial) && (q.get("operator_id") === null || u.operator_id === q.get("operator_id")) && (q.get("status") === null || u.status === q.get("status")));
      return json(res, 200, { uas: rows }), true;
    }
    if (p === "/v1/registry/uas" && m === "POST") {
      if (!R(["registrar"])) return true;
      const now = iso(Date.now());
      const u = { id: `uas-${++st.seq}`, manufacturer_code: "TEST", manufacturer: "", model: "", status: "active", status_reason: "", registered_at: now, registry_version: st.seq, created_by: s.sub, updated_at: now, updated_by: s.sub, ...body };
      st.uas.set(u.id, u);
      return json(res, 201, u), true;
    }
    if (p === "/v1/registry/pilots" && m === "GET") {
      if (!R(["registrar", "inspector", "viewer"])) return true;
      const rows = [...st.pilots.values()].filter((x) => (q.get("operator_id") === null || x.operator_id === q.get("operator_id")) && (q.get("status") === null || x.status === q.get("status")));
      return json(res, 200, { pilots: rows }), true;
    }
    if (p === "/v1/registry/pilots" && m === "POST") {
      if (!R(["registrar"])) return true;
      const now = iso(Date.now());
      const x = { id: `pil-${++st.seq}`, ...(body.operator_id === undefined ? {} : { operator_id: body.operator_id }), status: "active", status_reason: "", competencies: [], registry_version: st.seq, created_at: now, created_by: s.sub, updated_at: now, updated_by: s.sub };
      st.pilots.set(x.id, x);
      st.pilotPii.set(x.id, { pilot_id: x.id, name: body.name, person_ref_last4: String(body.person_ref ?? "").slice(-4) });
      return json(res, 201, x), true;
    }
    if (p === "/v1/registry/import" && m === "POST") {
      if (!R(["registrar"])) return true;
      const kind = q.get("kind");
      if (kind !== "operators" && kind !== "uas") return problem(res, 400, "validation", "Invalid request", "", [{ field: "kind", reason: "operators or uas" }]), true;
      const lines = raw.split(/\r?\n/).filter((l) => l.trim() !== "");
      const records = lines.slice(1);
      const problems = [];
      const outcomes = [];
      records.forEach((l, i) => {
        if (/BAD/.test(l)) problems.push({ field: `records[${i + 1}].registration_number`, reason: "does not match the rules file's registration_number_pattern" });
        else outcomes.push({ record: i + 1, source_id: l.split(/[;,]/)[0] ?? "", action: "created", status: "active" });
      });
      const dry = q.get("dry_run") === "true";
      const report = { kind, dry_run: dry, applied: !dry && problems.length === 0, records: records.length, created: outcomes.length, updated: 0, unchanged: 0, rules_version: "test-rules-1", content_sha256: "0".repeat(64), problems, outcomes, ...(dry || problems.length > 0 ? {} : { registry_version: ++st.seq }) };
      if (!dry && problems.length > 0) return problem(res, 422, "import_refused", "Import refused", "nothing was written", problems), true;
      return json(res, 200, report), true;
    }
    if (p === "/v1/registry/applications" && m === "GET") {
      if (!R(["registrar"])) return true;
      if (!st.applicationsOn) return problem(res, 404, "not_found", "Not found", "applications are off"), true;
      return json(res, 200, { applications: st.applications.filter((a) => q.get("state") === null || a.state === q.get("state")) }), true;
    }
    if ((g = /^\/v1\/registry\/applications\/([^/]+)\/(personal-data|review|approve|refuse)$/.exec(p))) {
      if (!R(["registrar"])) return true;
      if (!st.applicationsOn) return problem(res, 404, "not_found", "Not found", "applications are off"), true;
      const a = st.applications.find((x) => x.application_id === g[1]);
      if (a === undefined) return problem(res, 404, "not_found", "Not found", g[1]), true;
      if (g[2] === "personal-data") {
        if ((q.get("purpose") ?? "") === "") return problem(res, 400, "validation", "Invalid request", "", [{ field: "purpose", reason: "required" }]), true;
        return json(res, 200, { application_id: a.application_id, operator_type: a.operator_type, legal_name: "Test Company LLC", legal_identification_number: "TEST000000", postal_address: "2 Test Street", contact_email: "company@example.test", contact_phone: "+995000000003" }), true;
      }
      if (g[2] === "review") Object.assign(a, { state: "under_review", review_started_at: iso(Date.now()), registrar_id: s.sub });
      if (g[2] === "approve") Object.assign(a, { state: "approved", decided_at: iso(Date.now()), registration_number: "GEOTEST00000099", operator_id: "op-99", valid_until: body?.valid_until ?? "2027-10-01T00:00:00Z" });
      if (g[2] === "refuse") Object.assign(a, { state: "refused", decided_at: iso(Date.now()), refusal_reason: body?.reason });
      return json(res, 200, a), true;
    }

    // --- zones and U-space ------------------------------------------------
    const zr = /^\/v1\/(zones|uspace)(\/(.+))?$/.exec(p);
    if (zr) {
      const ds = zr[1] === "zones" ? "zones" : "uspace_airspace";
      const rest = zr[3] ?? "";
      const read = ds === "zones" ? ["inspector", "admin", "viewer"] : ["admin"];
      const author = ds === "zones" ? ["inspector"] : ["admin"];
      if (rest === "" && m === "GET") {
        if (!R(read)) return true;
        return json(res, 200, { zones: listZones(ds, q.get("state")) }), true;
      }
      if (rest === "" && m === "POST") {
        if (!R(author)) return true;
        const r = draftOf(ds, body, null, s);
        return r.errors ? (problem(res, 400, "validation", "Invalid request", "", r.errors), true) : (json(res, 201, r.version), true);
      }
      if (rest === "publish" && m === "POST") {
        if (!R(["admin"])) return true;
        const approved = listZones(ds, "approved");
        if (approved.length === 0) return problem(res, 409, "nothing_to_publish", "Nothing to publish", `no ${ds} version is approved`), true;
        for (const v of approved) {
          for (const o of st.zones.get(v.identifier)) if (o.state === "published") o.state = "superseded";
        }
        const row = publicationRow(ds, 0, s.sub);
        for (const v of approved) Object.assign(st.zones.get(v.identifier).find((o) => o.zone_version === v.zone_version), { state: "published", published_version: row.version, published_at: iso(Date.now()), published_by: s.sub });
        row.feature_count = listZones(ds, "published").length;
        return json(res, 200, { dataset: ds, zones_version: row.version, published: approved, publication: { id: row.id, dataset: ds, version: row.version, payload_hash: row.payload_hash, feature_count: row.feature_count, signature: null, state: "pending", created_at: row.created_at } }), true;
      }
      if (rest === "import" && m === "POST" && ds === "zones") {
        if (!R(author)) return true;
        const r = importZones(raw, q, s);
        return r.errors ? (problem(res, 400, "validation", "Invalid request", "the import is all or nothing: nothing was imported", r.errors), true) : (json(res, 201, r.result), true);
      }
      if (rest === "export" && m === "GET" && ds === "zones") {
        if (!R(read)) return true;
        return json(res, 200, { type: "FeatureCollection", features: listZones("zones", "published").map(featureOf) }, { "Content-Type": "application/geo+json" }), true;
      }
      const one = /^([^/]+)(\/(approve|designate|versions|applies))?$/.exec(rest);
      if (one) {
        const vs = st.zones.get(one[1]);
        const sub = one[3];
        if (sub === undefined && m === "PUT") {
          if (!R(author)) return true;
          if (vs === undefined) return problem(res, 404, "not_found", "Not found", one[1]), true;
          const r = draftOf(ds, body, one[1], s);
          return r.errors ? (problem(res, 400, "validation", "Invalid request", "", r.errors), true) : (json(res, 201, r.version), true);
        }
        if (vs === undefined || newest(vs).dataset !== ds) return R(read) ? (problem(res, 404, "not_found", "Not found", one[1]), true) : true;
        if (sub === undefined && m === "GET") return R(read) ? (json(res, 200, newest(vs)), true) : true;
        if (sub === "versions" && m === "GET") return R(read) ? (json(res, 200, { versions: [...vs].reverse() }), true) : true;
        if (sub === "applies" && m === "GET") {
          if (!R(read)) return true;
          const at = q.get("at");
          const v = newest(vs);
          const a = at === null ? "unknown" : Date.parse(v.valid_from) <= Date.parse(at) && Date.parse(at) < Date.parse(v.valid_to) ? "applies" : "not_applicable";
          return json(res, 200, { identifier: v.identifier, zone_version: v.zone_version, at, applicability: a, ...(a === "not_applicable" ? { reason: "outside the period of validity" } : {}) }), true;
        }
        if ((sub === "approve" && ds === "zones") || (sub === "designate" && ds === "uspace_airspace")) {
          if (!R(["admin"])) return true;
          const v = newest(vs);
          if (v.zone_version !== body?.zone_version || v.state !== "draft") return problem(res, 409, "conflict", "Not the newest draft", "", [{ field: "zone_version", reason: "must be the newest version and a draft" }]), true;
          Object.assign(v, { state: "approved", approved_at: iso(Date.now()), approved_by: s.sub });
          return json(res, 200, v), true;
        }
      }
    }
    if (p === "/v1/publications" && m === "GET") {
      if (!R(["admin", "inspector", "viewer"])) return true;
      return json(res, 200, publicationsOut(q.get("dataset") ?? undefined, Number(q.get("limit") ?? "20"))), true;
    }

    // --- certificates ---------------------------------------------------------
    if (p === "/v1/certificates/register" && m === "GET") {
      return (
        json(res, 200, {
          generated_at: iso(Date.now()),
          certificates: [...st.certs.values()].map((c) => ({ certificate_id: c.id, holder: c.holder, holder_name: c.holder_name, code: c.code, services: c.services, status: c.status, valid_from: c.issued_at, valid_until: c.valid_until, limitations: c.limitations })),
        }),
        true
      );
    }
    if (p === "/v1/certificates" && m === "GET") {
      if (!R(["admin"])) return true;
      return json(res, 200, { certificates: [...st.certs.values()].filter((c) => (q.get("status") === null || c.status === q.get("status")) && (q.get("holder") === null || c.holder === q.get("holder"))) }), true;
    }
    if (p === "/v1/certificates" && m === "POST") {
      if (!R(["admin"])) return true;
      if ([...st.certs.values()].some((c) => c.code === body?.code)) return problem(res, 409, "conflict", "Code in use", "", [{ field: "code", reason: "in use" }]), true;
      const now = iso(Date.now());
      const c = { id: id16() + id16(), holder_address: "", holder_email: "", holder_phone: "", holder_url: "", base_url: "", conditions: "", limitations: [], terms_url: "", ...body, client_id: `${body.holder === "cisp" ? "cisp" : `ussp-${body.code}`}-01`, issued_at: body.valid_from ?? now, status: "issued", operations: "not_started", limited: false, suspended: false, status_reason: "", status_changed_at: now, status_changed_by: s.sub, lapse_unused_after_months: 6, lapse_ceased_after_months: 12, lapses_at: iso(Date.now() + 180 * 86400_000), created_at: now, created_by: s.sub, updated_at: now, updated_by: s.sub };
      delete c.jwks;
      delete c.auth_method;
      delete c.valid_from;
      st.certs.set(c.id, c);
      st.notices.set(c.id, []);
      return json(res, 201, { certificate: c, client: { client_id: c.client_id, status: "active", scopes: ["registry.validate", "cis.read"], audiences: ["127.0.0.1"], auth_method: body.auth_method }, ...(body.auth_method === "client_secret_post" ? { client_secret: `test-secret-${id16()}` } : {}) }), true;
    }
    if (p === "/v1/certificates/publish-list" && m === "POST") {
      if (!R(["admin"])) return true;
      const row = publicationRow("ussp_list", [...st.certs.values()].filter((c) => c.holder === "ussp" && c.status === "operating").length, s.sub);
      return json(res, 200, { publication_id: row.id, ussps: row.feature_count, wanted: row.version }), true;
    }
    if ((g = /^\/v1\/certificates\/([0-9a-f]{32})(\/(status-notices|suspend|limit|revoke|reinstate))?$/.exec(p))) {
      if (!R(["admin"])) return true;
      const c = st.certs.get(g[1]);
      if (c === undefined) return problem(res, 404, "not_found", "Not found", g[1]), true;
      const act = g[3];
      if (act === undefined && m === "GET") return json(res, 200, { certificate: c, client_status: c.status === "revoked" ? "revoked" : c.suspended ? "suspended" : "active", notices: st.notices.get(c.id) }), true;
      if (act === undefined && m === "PATCH") {
        Object.assign(c, body);
        return json(res, 200, certChange(c, s, "not_needed")), true;
      }
      const ended = c.status === "revoked" || c.status === "lapsed";
      if (ended) return problem(res, 409, "certificate_ended", "Ended", "revoked or lapsed is final"), true;
      if (act !== "status-notices" && (typeof body?.reason !== "string" || body.reason.trim() === "")) return problem(res, 400, "validation", "Invalid request", "", [{ field: "reason", reason: "required" }]), true;
      if (act === "suspend") Object.assign(c, { suspended: true, status_reason: body.reason, status_changed_at: iso(Date.now()), status_changed_by: s.sub });
      if (act === "reinstate") Object.assign(c, c.suspended ? { suspended: false } : { limited: false, limitations: [] }, { status_reason: body.reason });
      if (act === "limit") Object.assign(c, { limited: true, limitations: body.limitations, status_reason: body.reason });
      if (act === "revoke") Object.assign(c, { status: "revoked", ended_at: iso(Date.now()), status_reason: body.reason });
      if (act === "status-notices") {
        const n = { id: ++st.seq, state: body.state, at: body.at, reference: body.reference, source: "manual", recorded_by: s.sub, received_at: iso(Date.now()) };
        st.notices.get(c.id).push(n);
        c.operations = body.state === "ceased" ? "ceased" : "operating";
        return json(res, 201, { notice: n, ...certChange(c, s), replayed: false }), true;
      }
      const out = certChange(c, s);
      return json(res, 200, act === "suspend" || act === "revoke" ? { ...out, tokens_valid_until: iso(Date.now() + 3600_000) } : out), true;
    }
    return false;
  }

  function control(path, input) {
    if (path === "requests") return requests;
    if (path === "cisp" && input.ack === true) {
      for (const r of st.publications)
        if (r.state === "pending" || r.state === "sent") Object.assign(r, { state: "acknowledged", attempts: r.attempts + 1, last_status: 201, cisp_version: r.version, acknowledged_at: iso(Date.now()), state_changed_at: iso(Date.now()) });
      return { acknowledged: true };
    }
    if (path === "state") {
      if (input.applications === "off") st.applicationsOn = false;
      if (input.applications === "on") st.applicationsOn = true;
      return { applications: st.applicationsOn ? "on" : "off" };
    }
    return null;
  }

  return { handle, reset, control, requests };
}

