// The overview reads each of api's counts only for the roles its
// operation admits (api/openapi.yaml x-roles of /v1/overview/*), so a
// role outside it is never shown a refusal it could not avoid; and the
// status lists the tiles walk are the contract's enums.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CERTIFICATE_STATUSES, REGISTRY_STATUSES, ZONE_STATES } from "./figures";
import { SUMMARY_ROLES } from "./Overview";

const spec = readFileSync(new URL("../../../api/openapi.yaml", import.meta.url), "utf8").replace(/\r\n/g, "\n");

/** The x-roles of GET path in the contract. */
function rolesOf(path: string): string[] {
  const at = spec.indexOf(`\n  ${path}:\n    get:\n`);
  expect(at, path).toBeGreaterThan(0);
  const m = /\n {6}x-roles: \[([^\]]*)\]/.exec(spec.slice(at, spec.indexOf("\n  /", at + 1)));
  expect(m, path).not.toBeNull();
  return (m?.[1] ?? "").split(",").map((r) => r.trim());
}

function enumOf(schema: string): string[] {
  const m = new RegExp(String.raw`\n    ${schema}:\n      type: string\n      enum: \[([^\]]*)\]`).exec(spec);
  expect(m, schema).not.toBeNull();
  return (m?.[1] ?? "").split(",").map((r) => r.trim());
}

describe("the overview's counts", () => {
  it("are read by exactly the roles their operations admit", () => {
    for (const [domain, roles] of Object.entries(SUMMARY_ROLES)) {
      expect([...roles].sort(), domain).toEqual(rolesOf(`/v1/overview/${domain}`).sort());
    }
  });

  it("a role the contract does not admit is found (the pair above)", () => {
    expect(rolesOf("/v1/overview/certificates")).not.toContain("viewer");
    expect(rolesOf("/v1/overview/audit")).toContain("auditor");
  });

  it("walk the contract's statuses in its order", () => {
    expect([...REGISTRY_STATUSES]).toEqual(enumOf("RegistryStatus"));
    expect([...ZONE_STATES]).toEqual(enumOf("ZoneState"));
    expect([...CERTIFICATE_STATUSES]).toEqual(enumOf("CertificateStatus"));
  });
});
