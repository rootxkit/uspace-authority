import path from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const root = path.dirname(fileURLToPath(import.meta.url));

// The image is built once in CI (`output: "standalone"`) and configured
// at start: nothing here reads the environment, and there are no
// rewrites. In a deployment Caddy routes /v1/picture/* to picture-ws,
// /v1/*, /oauth/* and /.well-known/* to api and /basemap/* to the shared
// basemap volume (docs/PLAN.md §10); locally scripts/dev-origin.mjs
// stands in for it (docs/runbooks/web.md).
const config: NextConfig = {
  output: "standalone",
  outputFileTracingRoot: root,
  turbopack: { root },
  poweredByHeader: false,
  reactStrictMode: true,
  // The CSP is set per request with its nonce in proxy.ts (src/csp.ts);
  // these hold for every response, assets included.
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

export default config;
