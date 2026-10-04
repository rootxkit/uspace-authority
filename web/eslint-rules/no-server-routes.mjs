// Spec 00 §6.2 and docs/PLAN.md §1.1: Next.js renders, and its only
// server code is the BFF. Route handlers live under app/%5Fbff/ (the URL
// /_bff/*; the App Router ignores folders that start with "_") and, with
// the module that configures them (src/lib/bff/), import only the kit's
// BFF helpers, next/server and the generated API types. No other
// app/**/route.ts may exist: the console has no API of its own.

const BFF_ROUTE = /(?:^|\/)app\/(?:_bff|%5[Ff]bff)\//;
const BFF_MODULE = /(?:^|\/)src\/lib\/bff\/[^/]+$/;
const ROUTE_FILE = /(?:^|\/)app\/(?:.*\/)?route\.(?:[cm]?[jt]sx?)$/;
const TEST_FILE = /\.test\.[cm]?[jt]sx?$/;

const BFF_ALLOWED = [/^@rootxkit\/uspace-ui\/auth\/server$/, /^next\/server(?:\.js)?$/, /^@\/src\/api\/types$/];
// A route file may also import the one module that configures the kit.
const ROUTE_ALLOWED = [...BFF_ALLOWED, /^@\/src\/lib\/bff\/handlers$/];

/** Every static module specifier in a file (import, export ... from, import(), require()). */
function visitSources(visit) {
  const fromSource = (node) => {
    const s = node.source;
    if (s && s.type === "Literal" && typeof s.value === "string") visit(s.value, node);
  };
  return {
    ImportDeclaration: fromSource,
    ExportNamedDeclaration: fromSource,
    ExportAllDeclaration: fromSource,
    ImportExpression: fromSource,
    CallExpression(node) {
      if (node.callee.type !== "Identifier" || node.callee.name !== "require") return;
      const a = node.arguments[0];
      if (a && a.type === "Literal" && typeof a.value === "string") visit(a.value, node);
    },
  };
}

/** @type {import("eslint").Rule.RuleModule} */
export default {
  meta: {
    type: "problem",
    docs: { description: "Keeps server-side code to the BFF's three routes (00 §6.2)." },
    schema: [],
    messages: {
      forbidden:
        "'{{source}}' is not allowed here. The BFF imports only @rootxkit/uspace-ui/auth/server, next/server and src/api/types; business logic belongs to api.",
      route: "A route handler outside app/%5Fbff/ (the /_bff/* routes). web/ has no other server routes.",
    },
  },
  create(context) {
    const file = context.filename.replaceAll("\\", "/");
    if (TEST_FILE.test(file)) return {};
    const isBffRoute = BFF_ROUTE.test(file);
    if (ROUTE_FILE.test(file) && !isBffRoute) {
      return {
        Program(node) {
          context.report({ node, messageId: "route" });
        },
      };
    }
    const allowed = isBffRoute ? ROUTE_ALLOWED : BFF_MODULE.test(file) ? BFF_ALLOWED : null;
    if (allowed === null) return {};
    return visitSources((source, node) => {
      if (!allowed.some((re) => re.test(source))) context.report({ node, messageId: "forbidden", data: { source } });
    });
  },
};
