// The lockfile backstop of no-restricted-imports: every package pnpm
// installs, direct or transitive, against the same list. It finds the
// forbidden packages a dependency pulls in, leaves the names that only
// resemble them, and passes the real lockfile.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { forbiddenInLockfile, lockfilePackages } from "./check-lockfile.mjs";

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(path.join(webRoot, p), "utf8");

describe("check-lockfile", () => {
  it("reads every package of the lockfile, scoped and tarball ones included", () => {
    expect([...lockfilePackages(read("test/fixtures/forbidden-lock.yaml"))].sort()).toEqual([
      "@nats-io/nkeys",
      "@rootxkit/uspace-ui",
      "jose",
      "josephus",
      "next",
      "pg-protocol",
    ]);
  });

  it("finds a forbidden package that is only a transitive dependency", () => {
    expect(forbiddenInLockfile(read("test/fixtures/forbidden-lock.yaml"))).toEqual(["@nats-io/nkeys", "jose", "pg-protocol"]);
  });

  it("passes web/'s own lockfile (the pair above), which it reads in full", () => {
    const text = read("pnpm-lock.yaml");
    expect(lockfilePackages(text).size).toBeGreaterThan(100);
    expect(lockfilePackages(text).has("next")).toBe(true);
    expect(forbiddenInLockfile(text)).toEqual([]);
  });
});
