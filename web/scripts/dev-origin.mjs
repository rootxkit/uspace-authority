#!/usr/bin/env node
// A local stand-in for the deployment's Caddy (docs/PLAN.md §10), for
// running the console against real api and picture-ws processes: one
// origin, routed by path as in a deployment. Development only; the
// deployment's Caddy is composed by uspace-deploy.
//
//   DEV_ORIGIN_PORT=3000 \
//   DEV_WEB_URL=http://127.0.0.1:3100 \
//   DEV_API_URL=http://127.0.0.1:8080 \
//   DEV_PICTURE_URL=http://127.0.0.1:8090 \
//   [DEV_BASEMAP_DIR=/path/to/basemap] node scripts/dev-origin.mjs
//
// /v1/picture/* (HTTP and the WebSocket upgrade) -> DEV_PICTURE_URL;
// /v1/*, /oauth/*, /.well-known/* -> DEV_API_URL; /basemap/* -> files
// under DEV_BASEMAP_DIR (404 without it: the map says "no base map");
// everything else -> DEV_WEB_URL, with the X-Forwarded-* headers Caddy
// sets (the BFF trusts one hop: WEB_TRUSTED_PROXY_HOPS=1).
import { createReadStream, statSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";

const PORT = Number(process.env.DEV_ORIGIN_PORT ?? "3000");
const need = (name) => {
  const v = process.env[name];
  if (v === undefined || v === "") {
    console.error(`dev-origin: ${name} is not set`);
    process.exit(2);
  }
  return new URL(v);
};
const WEB = need("DEV_WEB_URL");
const API = need("DEV_API_URL");
const PICTURE = need("DEV_PICTURE_URL");
const BASEMAP = process.env.DEV_BASEMAP_DIR ?? "";

function upstreamOf(pathname) {
  if (pathname.startsWith("/v1/picture/")) return PICTURE;
  if (pathname.startsWith("/v1/") || pathname.startsWith("/oauth/") || pathname.startsWith("/.well-known/")) return API;
  return WEB;
}

function forwardedHeaders(req) {
  return {
    ...req.headers,
    "x-forwarded-for": req.socket.remoteAddress ?? "127.0.0.1",
    "x-forwarded-proto": "http",
    "x-forwarded-host": req.headers.host ?? `127.0.0.1:${PORT}`,
  };
}

function basemap(req, res, pathname) {
  const rel = decodeURIComponent(pathname.slice("/basemap/".length));
  const file = path.resolve(BASEMAP, rel);
  if (BASEMAP === "" || !file.startsWith(path.resolve(BASEMAP) + path.sep)) {
    res.writeHead(404).end();
    return;
  }
  try {
    if (!statSync(file).isFile()) throw new Error("not a file");
  } catch {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { "Cache-Control": "no-cache" });
  createReadStream(file).pipe(res);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://127.0.0.1:${PORT}`);
  if (url.pathname.startsWith("/basemap/")) return basemap(req, res, url.pathname);
  const up = upstreamOf(url.pathname);
  const proxied = http.request(
    { host: up.hostname, port: up.port, method: req.method, path: req.url, headers: forwardedHeaders(req) },
    (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers);
      r.pipe(res);
    },
  );
  proxied.on("error", (err) => {
    if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain" }).end(`dev-origin: ${up.origin}: ${err.message}`);
    else res.destroy(err);
  });
  req.pipe(proxied);
});

// The WebSocket upgrade: the raw request goes to picture-ws as it came
// (the Origin and the cookie with it), then the bytes are piped both ways.
server.on("upgrade", (req, socket, head) => {
  const up = upstreamOf(new URL(req.url ?? "/", "http://x").pathname);
  const conn = net.connect(Number(up.port), up.hostname, () => {
    const lines = [`${req.method} ${req.url} HTTP/1.1`];
    for (const [k, v] of Object.entries(forwardedHeaders(req))) {
      for (const one of Array.isArray(v) ? v : [v]) if (one !== undefined) lines.push(`${k}: ${one}`);
    }
    conn.write(`${lines.join("\r\n")}\r\n\r\n`);
    if (head.length > 0) conn.write(head);
    conn.pipe(socket);
    socket.pipe(conn);
  });
  const close = () => {
    conn.destroy();
    socket.destroy();
  };
  conn.on("error", close);
  socket.on("error", close);
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`dev-origin: http://127.0.0.1:${PORT} -> web ${WEB.origin}, api ${API.origin}, picture-ws ${PICTURE.origin}`);
});
