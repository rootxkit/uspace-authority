// The packages web/ never holds, with why (CLAUDE.md rule 10, docs/PLAN.md
// §3). One list for both checks: eslint.config.mjs's no-restricted-imports
// and scripts/check-lockfile.mjs, the CI backstop over every package the
// lockfile installs, direct or transitive. Patterns are the rule's
// (gitignore-style: "*" is any run of characters within one path segment).

/** The packages web/ never imports, with why. */
export const RESTRICTED = [
  { group: ["turf", "@turf/*"], message: "Geometry is judged once, in Go, on uspace-core (CLAUDE.md rule 3); web/ renders what api says." },
  { group: ["h3", "h3-js"], message: "No H3 anywhere (plan D3); the partition grid is core's geodesy/cell and never reaches the browser." },
  { group: ["proj4"], message: "No projection library in web/: MapLibre draws WGS84 as the API sends it." },
  { group: ["jose", "jsonwebtoken", "jwt-decode"], message: "No JWT library in web/: the BFF never verifies a token and the page never sees one (M20)." },
  { group: ["pg", "pg-*", "postgres"], message: "web/ has no database: it reads api through the BFF." },
  { group: ["nats", "nats.ws", "@nats-io/*"], message: "web/ has no bus: it reads picture-ws over its WebSocket." },
];
