// The navigation by role is the operations' x-roles (a courtesy, never a
// control): each WP-22 page is shown to the roles its read admits, and
// not to the others (E-01).
import { describe, expect, it } from "vitest";
import { navFor } from "./nav";

const paths = (roles: string[], realm = "console") => navFor({ roles, realm }).map((i) => i.path);

describe("navFor", () => {
  it("a registrar sees the registry, not zones, U-space or certificates", () => {
    expect(paths(["registrar"])).toEqual(["", "/registry/operators"]);
  });

  it("an inspector and a viewer see the registry and the zones", () => {
    expect(paths(["inspector"])).toEqual(["", "/registry/operators", "/zones", "/violations", "/incidents"]);
    expect(paths(["viewer"])).toEqual(["", "/registry/operators", "/zones"]);
  });

  it("an admin sees the zones, U-space airspaces and certificates, not the registry", () => {
    expect(paths(["admin"])).toEqual(["", "/zones", "/uspace", "/certificates", "/sources", "/audit"]);
  });

  it("the police realm sees no console navigation, whatever its roles (WP-23: its own layout)", () => {
    expect(paths(["admin", "registrar"], "police")).toEqual([]);
  });

  it("no session sees nothing", () => {
    expect(navFor(null)).toEqual([]);
  });
});
