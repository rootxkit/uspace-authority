// The stub api's overview counts (api/openapi.yaml /v1/overview/*), for
// test/mock-origin.mjs: fixed figures in the contract's shapes, each
// behind its operation's x-roles in the console realm (a police session
// is a 403 as api answers it). The figures are test data of this file.
//
// Control (tests only), through mock-origin:
//   POST /__mock/overview {refuse?: [domain...], auditMore?: boolean}
//     the domains answered 503 instead, and the audit count at its bound.

const ROLES = {
  registry: ["registrar", "inspector", "viewer"],
  uspace: ["admin"],
  certificates: ["admin"],
  audit: ["admin", "auditor"],
};

const counts = (active, suspended, revoked, expired) => ({ active, suspended, revoked, expired, total: active + suspended + revoked + expired });

/** The figures each domain answers, as of the request. */
function figures(domain, asOf, auditMore) {
  switch (domain) {
    case "registry":
      return { as_of: asOf, operators: counts(12, 2, 1, 3), uas: counts(31, 0, 4, 0), pilots: counts(9, 1, 0, 2) };
    case "uspace":
      return { as_of: asOf, draft: 1, approved: 0, published: 2, superseded: 0, total: 3 };
    case "certificates":
      return { as_of: asOf, issued: 1, operating: 3, ceased: 0, suspended: 1, limited: 0, revoked: 0, lapsed: 1, total: 6 };
    case "audit":
      return auditMore ? { as_of: asOf, window_s: 86400, events: 100000, more: true } : { as_of: asOf, window_s: 86400, events: 287, more: false };
  }
  return null;
}

let refuse = new Set();
let auditMore = false;

export function resetOverview() {
  refuse = new Set();
  auditMore = false;
}

export function overviewControl(input) {
  if (Array.isArray(input.refuse)) refuse = new Set(input.refuse.map(String));
  if (typeof input.auditMore === "boolean") auditMore = input.auditMore;
  return { refuse: [...refuse], auditMore };
}

/** Answers GET /v1/overview/<domain> for session s; false when the path is not one of them. */
export function overviewApi(req, res, url, s, problem, json) {
  const m = /^\/v1\/overview\/(registry|uspace|certificates|audit)$/.exec(url.pathname);
  if (m === null) return false;
  const domain = m[1];
  if (req.method !== "GET") return problem(res, 405, "method_not_allowed", "Method not allowed", `${req.method} is not served on this path`), true;
  if (s.realm !== "console") return problem(res, 403, "forbidden", "Forbidden", `a ${s.realm} session is refused on this console operation`), true;
  if (!s.roles.some((r) => ROLES[domain].includes(r))) return problem(res, 403, "forbidden", "Forbidden", `this operation admits ${ROLES[domain].join(", ")}`), true;
  if (refuse.has(domain)) return problem(res, 503, "unavailable", "Unavailable", "the database did not answer"), true;
  json(res, 200, figures(domain, new Date().toISOString(), auditMore));
  return true;
}
