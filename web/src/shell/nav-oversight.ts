// WP-23's console pages and the roles their reads admit (api/openapi.yaml
// x-roles; spec 01 §1 users). A courtesy to the layout, like every nav
// item: api decides each request. The occurrence reports are for the
// incident officer alone: the entry does not exist for another role,
// and the pages refuse to render for one (376/2014 Art. 15-16; the
// inspector reads no reporter, and this console does not offer it the
// reports at all).
import type { NavItem } from "./nav";

export const OVERSIGHT_NAV_ITEMS: readonly NavItem[] = [
  { path: "/violations", labelKey: "authority.nav.violations", roles: ["inspector"], realms: ["console"] },
  { path: "/incidents", labelKey: "authority.nav.incidents", roles: ["inspector", "incident_officer"], realms: ["console"] },
  { path: "/occurrences", labelKey: "authority.nav.occurrences", roles: ["incident_officer"], realms: ["console"] },
  { path: "/sources", labelKey: "authority.nav.sources", roles: ["admin"], realms: ["console"] },
  { path: "/audit", labelKey: "authority.nav.audit", roles: ["admin", "auditor"], realms: ["console"] },
];
