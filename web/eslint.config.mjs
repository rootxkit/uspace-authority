// The kit's configuration (typescript-eslint strict, react-hooks, jsx-a11y,
// and its four rules: no geometry imports, no database or bus clients, no
// business logic in routes, no hand-written API types), plus this
// repository's own:
//
// - no-restricted-imports for what web/ may never hold (CLAUDE.md rule 10,
//   docs/PLAN.md §3): geometry and geodesy (turf, h3, proj4), a JWT
//   library (jose), a database (pg) and the bus (nats). The kit's rules
//   cover most of them; this list is the repository's own statement of
//   the rule, and CI greps the lockfile as a backstop.
// - authority/no-jsx-literals: no display string in JSX outside the
//   ka/en catalogues (CLAUDE.md rule 12).
// - authority/no-server-routes: the BFF's three routes under
//   app/%5Fbff/ are the only route handlers, and they import only the
//   kit's BFF helpers, next/server and src/lib/bff/handlers.
import kit from "@rootxkit/uspace-ui/eslint";
import authority from "./eslint-rules/index.mjs";

/** The packages web/ never imports, with why. */
export const RESTRICTED = [
  { group: ["turf", "@turf/*"], message: "Geometry is judged once, in Go, on uspace-core (CLAUDE.md rule 3); web/ renders what api says." },
  { group: ["h3", "h3-js"], message: "No H3 anywhere (plan D3); the partition grid is core's geodesy/cell and never reaches the browser." },
  { group: ["proj4"], message: "No projection library in web/: MapLibre draws WGS84 as the API sends it." },
  { group: ["jose", "jsonwebtoken", "jwt-decode"], message: "No JWT library in web/: the BFF never verifies a token and the page never sees one (M20)." },
  { group: ["pg", "pg-*", "postgres"], message: "web/ has no database: it reads api through the BFF." },
  { group: ["nats", "nats.ws", "@nats-io/*"], message: "web/ has no bus: it reads picture-ws over its WebSocket." },
];

export default [
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "next-env.d.ts",
      "test-results/**",
      "playwright-report/**",
      // Files that must fail the project rules (eslint-rules/rules.test.ts).
      "eslint-rules/fixtures/**",
    ],
  },
  ...kit,
  {
    name: "uspace-authority/web",
    plugins: { authority },
    rules: {
      "no-restricted-imports": ["error", { patterns: RESTRICTED }],
      "authority/no-server-routes": "error",
    },
  },
  {
    name: "uspace-authority/web-display-strings",
    files: ["**/*.tsx"],
    rules: { "authority/no-jsx-literals": "error" },
  },
];
