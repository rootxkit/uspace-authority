// The kit's configuration (typescript-eslint strict, react-hooks, jsx-a11y,
// and its four rules: no geometry imports, no database or bus clients, no
// business logic in routes, no hand-written API types), plus this
// repository's own:
//
// - no-restricted-imports for what web/ may never hold (CLAUDE.md rule 10,
//   docs/PLAN.md §3): geometry and geodesy (turf, h3, proj4), a JWT
//   library (jose), a database (pg) and the bus (nats). The kit's rules
//   cover most of them; this list (eslint-rules/restricted.mjs) is the
//   repository's own statement of the rule. CI's backstop is
//   scripts/check-lockfile.mjs, which checks every package pnpm-lock.yaml
//   installs against the same list, transitive ones included, and a grep
//   for the imports in app/ and src/.
// - authority/no-jsx-literals: no display string in JSX outside the
//   ka/en catalogues (CLAUDE.md rule 12).
// - authority/no-server-routes: the BFF's three routes under
//   app/%5Fbff/ are the only route handlers, and they import only the
//   kit's BFF helpers, next/server and src/lib/bff/handlers.
import kit from "@rootxkit/uspace-ui/eslint";
import authority from "./eslint-rules/index.mjs";
import { RESTRICTED } from "./eslint-rules/restricted.mjs";

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
