// The navigation by role is the operations' x-roles (a courtesy, never a
// control): each WP-22 page is shown to the roles its read admits, and
// not to the others (E-01).
import { describe, expect, it } from "vitest";
import { NAV_ITEMS, isCurrent, navFor, navGroupsFor } from "./nav";

const paths = (roles: string[], realm = "console") => navFor({ roles, realm }).map((i) => i.path);

describe("navFor", () => {
  it("a registrar sees the registry, not zones, U-space or certificates", () => {
    expect(paths(["registrar"])).toEqual(["", "/picture", "/registry/operators"]);
  });

  it("an inspector and a viewer see the registry and the zones", () => {
    expect(paths(["inspector"])).toEqual(["", "/picture", "/registry/operators", "/zones", "/violations", "/incidents"]);
    expect(paths(["viewer"])).toEqual(["", "/picture", "/registry/operators", "/zones"]);
  });

  it("an admin sees the zones, U-space airspaces and certificates, not the registry", () => {
    expect(paths(["admin"])).toEqual(["", "/picture", "/zones", "/uspace", "/certificates", "/sources", "/audit"]);
  });

  it("the police realm sees no console navigation, whatever its roles (WP-23: its own layout)", () => {
    expect(paths(["admin", "registrar"], "police")).toEqual([]);
  });

  it("no session sees nothing", () => {
    expect(navFor(null)).toEqual([]);
    expect(navGroupsFor(null)).toEqual([]);
  });

  it("the sidebar groups hold the role's items in order, and a group with none is left out", () => {
    const groups = (roles: string[]) => navGroupsFor({ roles, realm: "console" }).map((g) => [g.group, g.items.map((i) => i.path)]);
    expect(groups(["inspector"])).toEqual([
      ["operations", ["", "/picture", "/violations", "/incidents"]],
      ["airspace", ["/zones"]],
      ["registry", ["/registry/operators"]],
    ]);
    expect(groups(["auditor"])).toEqual([
      ["operations", ["", "/picture"]],
      ["administration", ["/audit"]],
    ]);
  });
});

describe("isCurrent", () => {
  const item = (path: string) => {
    const i = NAV_ITEMS.find((n) => n.path === path);
    if (i === undefined) throw new Error(path);
    return i;
  };

  it("the overview is current on its own path only", () => {
    expect(isCurrent(item(""), "en", "/en")).toBe(true);
    expect(isCurrent(item(""), "en", "/en/zones")).toBe(false);
  });

  it("an item is current on its pages and its section's, not on a page that merely shares a prefix", () => {
    expect(isCurrent(item("/zones"), "ka", "/ka/zones")).toBe(true);
    expect(isCurrent(item("/zones"), "ka", "/ka/zones/TSTP001/edit")).toBe(true);
    expect(isCurrent(item("/registry/operators"), "en", "/en/registry/uas/uas-1")).toBe(true);
    expect(isCurrent(item("/incidents"), "en", "/en/incidentsx")).toBe(false);
    expect(isCurrent(item("/zones"), "en", "/ka/zones")).toBe(false);
  });
});
