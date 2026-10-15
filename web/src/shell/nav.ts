// The console's navigation by role (spec 01 §1 users and roles; docs/
// PLAN.md §7). A courtesy to the layout, never a control: the roles come
// from the session cookie decoded without verification (the kit's
// sessionClaimsUnverified, M20), an item hidden here is still served or
// refused by api and picture-ws, and a page reached by its address shows
// what they answer.
import type { components } from "../api/types";
import { OVERSIGHT_NAV_ITEMS } from "./nav-oversight";

export type Role = components["schemas"]["Role"];
export type Realm = components["schemas"]["Realm"];

/** Every console role (api/openapi.yaml Role). */
export const ROLES: readonly Role[] = ["viewer", "inspector", "registrar", "incident_officer", "admin", "auditor"];

export function isRole(v: unknown): v is Role {
  return typeof v === "string" && (ROLES as readonly string[]).includes(v);
}

/** The sidebar's groups, in the order they are shown. */
export const NAV_GROUPS = ["operations", "airspace", "registry", "administration"] as const;
export type NavGroupId = (typeof NAV_GROUPS)[number];

/** The icon a page is shown with (src/shell/icons.tsx). */
export type NavIcon =
  | "overview"
  | "picture"
  | "violations"
  | "incidents"
  | "occurrences"
  | "zones"
  | "uspace"
  | "registry"
  | "certificates"
  | "sources"
  | "audit";

export interface NavItem {
  /** The path under /<locale>. */
  path: string;
  /** The sidebar group it is listed in. */
  group: NavGroupId;
  icon: NavIcon;
  /** The path prefix whose pages mark the item current, when wider than `path`. */
  section?: string;
  /** The catalogue key of its label. */
  labelKey: string;
  /** The roles the page's reads admit; empty means any session of the realm. */
  roles: readonly Role[];
  /** The realms the page is for. */
  realms: readonly Realm[];
}

/**
 * Every page of the console realm. The overview reads what each role's
 * reads admit and leaves out the rest. The live picture reads the picture,
 * which picture-ws serves to every session of the console realm, and
 * the zones, which api serves to inspector, admin and viewer (the map
 * says so when the zones are refused). The police realm has its own
 * layout and no console navigation (WP-23, src/police/). Later work
 * packages (WP-22 to WP-24) add their pages here with their operations'
 * x-roles.
 */
export const NAV_ITEMS: readonly NavItem[] = [
  { path: "", group: "operations", icon: "overview", labelKey: "authority.nav.overview", roles: [], realms: ["console"] },
  { path: "/picture", group: "operations", icon: "picture", labelKey: "authority.nav.map", roles: [], realms: ["console"] },
  // WP-22: the registry, zone and U-space authoring, certificates. The
  // roles are each page's read operation's x-roles (listRegistryOperators,
  // listZones, listUSpaceAirspaces, listCertificates).
  { path: "/registry/operators", section: "/registry", group: "registry", icon: "registry", labelKey: "authority.nav.registry", roles: ["registrar", "inspector", "viewer"], realms: ["console"] },
  { path: "/zones", group: "airspace", icon: "zones", labelKey: "authority.nav.zones", roles: ["inspector", "admin", "viewer"], realms: ["console"] },
  { path: "/uspace", group: "airspace", icon: "uspace", labelKey: "authority.nav.uspace", roles: ["admin"], realms: ["console"] },
  { path: "/certificates", group: "registry", icon: "certificates", labelKey: "authority.nav.certificates", roles: ["admin"], realms: ["console"] },
  // WP-23: violations, incidents, occurrences, sources, the audit log.
  ...OVERSIGHT_NAV_ITEMS,
];

/** Whether `item` is the current page's entry: the overview on its own path only, every other one on its section's pages too. */
export function isCurrent(item: NavItem, lang: string, pathname: string): boolean {
  const base = `/${lang}${item.section ?? item.path}`;
  if (item.path === "") return pathname === base;
  return pathname === base || pathname.startsWith(`${base}/`);
}

/** The items a session shows, by sidebar group in NAV_GROUPS order; a group with none is left out. */
export function navGroupsFor(session: { roles: readonly string[]; realm: string } | null): { group: NavGroupId; items: NavItem[] }[] {
  const items = navFor(session);
  return NAV_GROUPS.map((group) => ({ group, items: items.filter((i) => i.group === group) })).filter((g) => g.items.length > 0);
}

/** The items a session with `roles` in `realm` is shown; none without a session. */
export function navFor(session: { roles: readonly string[]; realm: string } | null): NavItem[] {
  if (session === null) return [];
  return NAV_ITEMS.filter(
    (i) =>
      (i.realms as readonly string[]).includes(session.realm) &&
      (i.roles.length === 0 || i.roles.some((r) => session.roles.includes(r))),
  );
}

/** The roles of a session the console has words for, in the catalogue's order. */
export function knownRoles(roles: readonly string[]): Role[] {
  return ROLES.filter((r) => roles.includes(r));
}
