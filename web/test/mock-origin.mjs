#!/usr/bin/env node
// The Playwright fixture server: a stand-in for the deployment's Caddy in
// front of `next start`, with a stub api and a stub picture-ws behind it,
// so the browser sees one origin as in a deployment.
//
//   MOCK_PORT=3000 MOCK_UPSTREAM=http://127.0.0.1:3100 node test/mock-origin.mjs
//
// - api (the shapes of api/openapi.yaml): POST /v1/auth/login, POST
//   /v1/auth/mfa, GET /v1/auth/session, POST /v1/auth/logout, the
//   registry, zone, U-space, publication and certificate operations of
//   test/mock/authoring.mjs (WP-22), which holds the zones too, and
//   WP-23's operations (test/mock-oversight.mjs). The BFF
//   reaches these here too (WEB_API_INTERNAL_URL).
// - picture-ws (docs/runbooks/picture.md): WS /v1/picture/ws with the
//   same-origin and cookie rules of M22 (a foreign Origin is 403, no
//   live session is a 4401 close), and GET /v1/picture/sources. On
//   every console/subscribe/v1 it sends console/status/v1 and
//   console/snapshot/v1, then a status every second and a track every
//   second. The frames are the lab's console/* examples
//   (../internal/picture/testdata/lab, verbatim copies at the commit in
//   its SOURCE) with their times moved to now, plus the fixtures in
//   test/fixtures: a full violation/v1 and a provider track that carries
//   an operator position and a registration number with a secret part,
//   which the console must never show.
// - Everything else goes to Next.js with the X-Forwarded-* headers Caddy
//   sets.
//
// Control (tests only):
//   GET  /__mock/health
//   POST /__mock/reset                    every session ended, bus connected
//   POST /__mock/state {nats?: "connected"|"unavailable", revoke?: true}
//   GET  /__mock/requests                 the api requests answered: method, path, body keys
//   GET  /__mock/subscribes               the console/subscribe/v1 bodies received
//   /__mock/authoring/*                   test/mock/authoring.mjs's controls
//   GET  /__mock/oversight                the police queries the stub recorded
//   GET  /__mock/upgrades                 the picture WebSocket upgrades: the realm of each
//
// The accounts and the code below are test data of this file, not
// credentials of anything.
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";
import { AUTHORING_ACCOUNTS, createAuthoring } from "./mock/authoring.mjs";
import { oversightApi, oversightRecords, publicApi, resetOversight } from "./mock-oversight.mjs";

const PORT = Number(process.env.MOCK_PORT ?? "3000");
const UPSTREAM = new URL(process.env.MOCK_UPSTREAM ?? "http://127.0.0.1:3100");
const ORIGIN = `http://127.0.0.1:${PORT}`;
const STATUS_PERIOD_MS = 1000;
const TRACK_PERIOD_MS = 1000;
const CODE = "246810";
const ACCOUNTS = {
  // WP-22's accounts (viewer1, admin1) in the console realm; the list below wins on a name.
  ...Object.fromEntries(Object.entries(AUTHORING_ACCOUNTS).map(([name, a]) => [name, { ...a, realm: "console" }])),
  inspector1: { password: "inspector1-test-password", roles: ["inspector"], realm: "console" },
  registrar1: { password: "registrar1-test-password", roles: ["registrar"], realm: "console" },
  officer1: { password: "officer1-test-password", roles: ["incident_officer"], realm: "console" },
  admin1: { password: "admin1-test-password", roles: ["admin"], realm: "console" },
  auditor1: { password: "auditor1-test-password", roles: ["auditor"], realm: "console" },
  police1: { password: "police1-test-password", roles: ["police.query"], realm: "police" },
};

const lab = (p) => JSON.parse(readFileSync(new URL(`../../internal/picture/testdata/lab/${p}`, import.meta.url), "utf8"));
const fixture = (p) => JSON.parse(readFileSync(new URL(`./fixtures/${p}`, import.meta.url), "utf8"));
const LAB_STATUS = lab("console/status/v1/examples/authority-picture.json");
const LAB_SNAPSHOT = lab("console/snapshot/v1/examples/authority-picture.json");
const LAB_NEVER_HEARD = lab("source/status/v1/examples/never-heard-type.json");
const VIOLATION = fixture("violation.json");
const PROVIDER_TRACK = fixture("provider-track.json");

let state;
let authoring = null;
const requests = [];
const subscribes = [];
/** Every picture WebSocket upgrade: the realm of its session, or null without one. */
const upgrades = [];
const sockets = new Set();

function reset() {
  state = { nats: "connected", natsSince: null, sessions: new Map(), challenges: new Map() };
  authoring?.reset();
  requests.length = 0;
  subscribes.length = 0;
  upgrades.length = 0;
  for (const s of sockets) s.close(1001);
  resetOversight();
}
reset();

// --- helpers -------------------------------------------------------------

const b64url = (v) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");
const iso = (ms) => new Date(ms).toISOString();

function json(res, status, payload, headers = {}) {
  const text = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), ...headers });
  res.end(text);
}

function problem(res, status, slug, title, detail) {
  json(res, status, { type: `https://schemas.uspace.ge/problems/${slug}`, title, status, detail }, { "Content-Type": "application/problem+json" });
}

function readText(req) {
  return new Promise((resolve) => {
    let text = "";
    req.on("data", (c) => (text += c));
    req.on("end", () => resolve(text));
  });
}

async function readJson(req) {
  const text = await readText(req);
  try {
    return text === "" ? {} : JSON.parse(text);
  } catch {
    return {};
  }
}

function cookie(req, name) {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

/** The live session of a bearer or a cookie token, or null. */
function sessionOf(token) {
  if (token === null) return null;
  const s = state.sessions.get(token);
  return s !== undefined && s.exp * 1000 > Date.now() ? s : null;
}

function bearer(req) {
  const h = req.headers.authorization ?? "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}

/** An unsigned token in the session shape (M20): the BFF never verifies, picture-ws here checks the map. */
function issueSession(username, roles, realm) {
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const jti = randomBytes(8).toString("hex");
  const payload = { iss: ORIGIN, aud: "127.0.0.1", sub: `user-${username}`, scope: "session", roles, realm, jti, iat: exp - 3600, exp };
  const token = `${b64url({ alg: "none", typ: "JWT" })}.${b64url(payload)}.`;
  state.sessions.set(token, { ...payload, username });
  return { token, payload };
}

function sessionInfo(s) {
  return {
    sub: s.sub,
    roles: s.roles,
    realm: s.realm,
    jti: s.jti,
    expires_at: iso(s.exp * 1000),
    idle_expires_at: iso(Date.now() + 30 * 60_000),
  };
}

// --- the stub api ----------------------------------------------------------

const ZONES = {
  zones: [
    {
      dataset: "zones",
      identifier: "TSTP001",
      zone_version: 2,
      state: "published",
      type: "PROHIBITED",
      country: "GEO",
      feature: {
        type: "Feature",
        geometry: {
          type: "Polygon",
          coordinates: [
            [
              [44.76, 41.69],
              [44.8, 41.69],
              [44.8, 41.73],
              [44.76, 41.73],
              [44.76, 41.69],
            ],
          ],
          layer: { lower: 0, lowerReference: "AGL", upper: 120, upperReference: "AGL", uom: "m" },
        },
        properties: { identifier: "TSTP001", country: "GEO", type: "PROHIBITED", name: [{ lang: "en-GB", text: "Test prohibited zone" }, { lang: "ka-GE", text: "სატესტო აკრძალული ზონა" }] },
      },
      valid_from: "2026-01-01T00:00:00Z",
      valid_to: "2027-01-01T00:00:00Z",
      extensions: [],
      published_version: 7,
      published_at: "2026-10-01T08:00:00Z",
      created_at: "2026-09-01T08:00:00Z",
      created_by: "user-test",
    },
    {
      dataset: "zones",
      identifier: "TSTC001",
      zone_version: 1,
      state: "published",
      type: "REQ_AUTHORIZATION",
      country: "GEO",
      feature: {
        type: "Feature",
        geometry: { type: "Point", coordinates: [44.85, 41.7], extent: { subType: "Circle", radius: 500 }, layer: { lower: 0, lowerReference: "AGL", upper: 60, upperReference: "AGL", uom: "m" } },
        properties: { identifier: "TSTC001", country: "GEO", type: "REQ_AUTHORIZATION" },
      },
      valid_from: "2026-01-01T00:00:00Z",
      valid_to: "2027-01-01T00:00:00Z",
      extensions: [],
      published_version: 7,
      published_at: "2026-10-01T08:00:00Z",
      created_at: "2026-09-01T08:00:00Z",
      created_by: "user-test",
    },
  ],
};

authoring = createAuthoring({ zonesSeed: ZONES.zones });

async function api(req, res, url) {
  const raw = req.method === "GET" ? "" : await readText(req);
  let body = {};
  try {
    body = raw === "" ? {} : JSON.parse(raw);
  } catch {
    body = {};
  }
  requests.push({ method: req.method, path: url.pathname, keys: Object.keys(body).sort(), query: [...url.searchParams.keys()].sort() });
  const p = url.pathname;
  if (publicApi(req, res, url)) return;
  if (p === "/v1/auth/login" && req.method === "POST") {
    const acct = ACCOUNTS[body.username];
    if (acct === undefined || acct.password !== body.password) return problem(res, 401, "invalid_credentials", "Sign-in refused", "the username or the password is wrong");
    const mfa = randomBytes(16).toString("hex");
    state.challenges.set(mfa, body.username);
    return json(res, 200, { mfa_token: mfa, expires_at: iso(Date.now() + 5 * 60_000) }, { "Cache-Control": "no-store" });
  }
  if (p === "/v1/auth/mfa" && req.method === "POST") {
    const username = state.challenges.get(body.mfa_token);
    if (username === undefined || body.code !== CODE) return problem(res, 401, "mfa_refused", "Code refused", "the code is wrong or the challenge is spent");
    state.challenges.delete(body.mfa_token);
    const { token, payload } = issueSession(username, ACCOUNTS[username].roles, ACCOUNTS[username].realm);
    return json(
      res,
      200,
      { token, token_type: "Bearer", expires_at: iso(payload.exp * 1000), idle_timeout_s: 1800, session: sessionInfo(state.sessions.get(token)) },
      { "Cache-Control": "no-store" },
    );
  }
  const s = sessionOf(bearer(req));
  if (s === null) return problem(res, 401, "unauthenticated", "No session", "sign in again");
  if (p === "/v1/auth/session" && req.method === "GET") return json(res, 200, sessionInfo(s));
  if (p === "/v1/auth/logout" && req.method === "POST") {
    state.sessions.delete(bearer(req));
    for (const ws of sockets) if (ws.token === bearer(req)) ws.close(4401);
    res.writeHead(204);
    return res.end();
  }
  // The registry, zones, U-space, publications and certificates (WP-22).
  if (authoring.handle(req, res, url, s, body, raw)) return;
  if (await oversightApi(req, res, url, s, body)) return;
  return problem(res, 404, "not_found", "Not found", `${req.method} ${p}`);
}

// --- the stub picture-ws -----------------------------------------------------

/** The lab's frame with every envelope time moved so that captured_at is `ageMs` ago. */
function fresh(frame, ageMs = 0) {
  const now = Date.now();
  const cap = iso(now - ageMs);
  return { ...frame, ts: frame.ts === null ? null : cap, captured_at: frame.captured_at === null ? null : cap, rx_ts: iso(now - Math.max(0, ageMs - 100)) };
}

function statusFrame(ws) {
  const now = Date.now();
  const lost = state.nats === "unavailable";
  const body = {
    ...LAB_STATUS.body,
    connection_id: ws.id,
    server_ts: iso(now),
    dropped_frames: ws.dropped,
    degraded: lost ? ["nats_unavailable"] : [],
    degraded_since: lost ? { nats_unavailable: state.natsSince } : {},
    sources: [...LAB_STATUS.body.sources, { ...LAB_NEVER_HEARD.body, source: "manned_feed" }],
    nats: state.nats,
    ...(lost ? { nats_since: state.natsSince } : {}),
  };
  return { ...LAB_STATUS, msg_id: `mock-status-${++ws.seq}`, ts: iso(now), rx_ts: iso(now), captured_at: iso(now), body };
}

function snapshotFrame(ws) {
  const now = Date.now();
  const tracks = [...LAB_SNAPSHOT.body.tracks.map((t) => fresh({ ...t, body: { ...t.body, age_s: 2, source_state: "live" } }, 2000)), fresh(PROVIDER_TRACK, 1400)];
  return {
    ...LAB_SNAPSHOT,
    msg_id: `mock-snapshot-${++ws.seq}`,
    ts: iso(now),
    rx_ts: iso(now),
    captured_at: iso(now),
    // The lab's alert example is its minimal shape; the full one is the fixture. Both are sent:
    // the console shows the full one and counts the other as refused.
    body: { ...LAB_SNAPSHOT.body, tracks, alerts: [...LAB_SNAPSHOT.body.alerts, fresh(VIOLATION, 0)], manned: [], truncated: false },
  };
}

function liveTrackFrame(ws) {
  const t = LAB_SNAPSHOT.body.tracks[1];
  return { ...fresh({ ...t, body: { ...t.body, age_s: 0.3, source_state: "live" } }, 300), msg_id: `mock-track-${++ws.seq}` };
}

function wsFrame(opcode, payload) {
  const len = payload.length;
  const head = len < 126 ? Buffer.from([0x80 | opcode, len]) : len < 65536 ? Buffer.alloc(4) : Buffer.alloc(10);
  if (len >= 126 && len < 65536) {
    head[0] = 0x80 | opcode;
    head[1] = 126;
    head.writeUInt16BE(len, 2);
  } else if (len >= 65536) {
    head[0] = 0x80 | opcode;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([head, payload]);
}

/** Client frames: masked, unfragmented text and close (RFC 6455 §5.2); enough for a subscribe. */
function readFrames(buf, onText, onClose) {
  let off = 0;
  while (buf.length - off >= 6) {
    const b0 = buf[off];
    const b1 = buf[off + 1];
    let len = b1 & 0x7f;
    let at = off + 2;
    if (len === 126) {
      if (buf.length - off < 8) break;
      len = buf.readUInt16BE(at);
      at += 2;
    } else if (len === 127) {
      if (buf.length - off < 14) break;
      len = Number(buf.readBigUInt64BE(at));
      at += 8;
    }
    if (buf.length < at + 4 + len) break;
    const mask = buf.subarray(at, at + 4);
    const data = Buffer.alloc(len);
    for (let i = 0; i < len; i++) data[i] = buf[at + 4 + i] ^ mask[i % 4];
    const opcode = b0 & 0x0f;
    if (opcode === 0x1) onText(data.toString("utf8"));
    if (opcode === 0x8) onClose();
    off = at + 4 + len;
  }
  return buf.subarray(off);
}

let connections = 0;
function upgrade(req, socket) {
  const url = new URL(req.url ?? "/", ORIGIN);
  const key = req.headers["sec-websocket-key"];
  if (url.pathname !== "/v1/picture/ws" || typeof key !== "string") {
    socket.end("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    return;
  }
  // M22: the Origin must be this origin exactly; nothing is read from the query string.
  if (req.headers.origin !== ORIGIN) {
    socket.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    return;
  }
  const accept = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  const ws = {
    id: `mock-c-${++connections}`,
    seq: 0,
    dropped: 0,
    token: cookie(req, "uspace_session"),
    subscribed: false,
    send(frame) {
      if (!socket.destroyed) socket.write(wsFrame(0x1, Buffer.from(JSON.stringify(frame))));
    },
    close(code) {
      if (socket.destroyed) return;
      const p = Buffer.alloc(2);
      p.writeUInt16BE(code, 0);
      socket.write(wsFrame(0x8, p));
      socket.end();
    },
  };
  upgrades.push({ realm: sessionOf(ws.token)?.realm ?? null });
  if (sessionOf(ws.token) === null) {
    ws.close(4401);
    return;
  }
  sockets.add(ws);
  const status = setInterval(() => {
    if (sessionOf(ws.token) === null) return ws.close(4401);
    ws.send(statusFrame(ws));
  }, STATUS_PERIOD_MS);
  const tracks = setInterval(() => {
    // With the bus lost nothing new arrives: the picture is frozen and ages.
    if (ws.subscribed && state.nats === "connected") ws.send(liveTrackFrame(ws));
  }, TRACK_PERIOD_MS);
  let pending = Buffer.alloc(0);
  socket.on("data", (chunk) => {
    pending = readFrames(
      Buffer.concat([pending, chunk]),
      (text) => {
        let frame;
        try {
          frame = JSON.parse(text);
        } catch {
          return ws.close(1007);
        }
        if (frame.schema !== "console/subscribe/v1") return ws.close(1007);
        subscribes.push(frame.body);
        ws.subscribed = true;
        ws.send(statusFrame(ws));
        ws.send(snapshotFrame(ws));
      },
      () => ws.close(1000),
    );
  });
  const end = () => {
    clearInterval(status);
    clearInterval(tracks);
    sockets.delete(ws);
  };
  socket.on("close", end);
  socket.on("error", end);
}

function pictureSources(req, res) {
  if (sessionOf(cookie(req, "uspace_session")) === null) return problem(res, 401, "unauthenticated", "No session", "sign in again");
  json(res, 200, { server_ts: iso(Date.now()), sources: [], nats: state.nats, nats_since: state.natsSince });
}

// --- control and the pass-through ---------------------------------------------

async function control(req, res, path) {
  if (path === "/__mock/health") return json(res, 200, { ok: true });
  if (path.startsWith("/__mock/authoring/")) {
    const out = authoring.control(path.slice("/__mock/authoring/".length), req.method === "POST" ? await readJson(req) : {});
    return out === null ? json(res, 404, { error: "unknown control" }) : json(res, 200, out);
  }
  if (path === "/__mock/requests") return json(res, 200, requests);
  if (path === "/__mock/subscribes") return json(res, 200, subscribes);
  if (path === "/__mock/oversight") return json(res, 200, oversightRecords());
  if (path === "/__mock/upgrades") return json(res, 200, upgrades);
  const input = await readJson(req);
  if (path === "/__mock/reset") {
    reset();
  } else if (path === "/__mock/state") {
    if (input.nats === "unavailable") {
      state.nats = "unavailable";
      state.natsSince = typeof input.natsSince === "string" ? input.natsSince : iso(Date.now());
    } else if (input.nats === "connected") {
      state.nats = "connected";
      state.natsSince = null;
    }
    if (input.revoke === true) {
      state.sessions.clear();
      for (const ws of sockets) ws.close(4401);
    }
  } else {
    return json(res, 404, { error: "unknown control" });
  }
  return json(res, 200, { nats: state.nats, natsSince: state.natsSince, sessions: state.sessions.size });
}

function passToNext(req, res) {
  const upstream = http.request(
    {
      host: UPSTREAM.hostname,
      port: UPSTREAM.port,
      method: req.method,
      path: req.url,
      // What Caddy sets: the BFF trusts one hop (WEB_TRUSTED_PROXY_HOPS)
      // and checks a sign-in's Origin against this scheme and host.
      headers: {
        ...req.headers,
        "x-forwarded-for": req.socket.remoteAddress ?? "127.0.0.1",
        "x-forwarded-proto": "http",
        "x-forwarded-host": req.headers.host ?? `127.0.0.1:${PORT}`,
      },
    },
    (up) => {
      res.writeHead(up.statusCode ?? 502, up.headers);
      up.pipe(res);
    },
  );
  upstream.on("error", (err) => {
    if (!res.headersSent) json(res, 502, { title: "upstream unreachable", detail: err.message });
    else res.destroy(err);
  });
  req.pipe(upstream);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", ORIGIN);
  if (url.pathname.startsWith("/__mock/")) return void control(req, res, url.pathname);
  if (url.pathname === "/v1/picture/sources") return pictureSources(req, res);
  if (url.pathname.startsWith("/basemap/")) return problem(res, 404, "not_found", "No basemap in the fixture", url.pathname);
  if (url.pathname.startsWith("/v1/")) return void api(req, res, url);
  passToNext(req, res);
});
server.on("upgrade", upgrade);
server.listen(PORT, "127.0.0.1", () => {
  console.log(`mock-origin: ${ORIGIN}, pages from ${UPSTREAM.origin}`);
});
