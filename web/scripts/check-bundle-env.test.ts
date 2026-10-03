import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { FORBIDDEN_ENV, scanBundle } from "./check-bundle-env.mjs";

const dirs: string[] = [];

function bundle(files: Record<string, string>): string {
  const dir = mkdtempSync(path.join(tmpdir(), "authority-bundle-"));
  dirs.push(dir);
  for (const [name, text] of Object.entries(files)) {
    const p = path.join(dir, name);
    mkdirSync(path.dirname(p), { recursive: true });
    writeFileSync(p, text);
  }
  return dir;
}

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("check-bundle-env", () => {
  it("passes a server bundle that names none of the forbidden variables", () => {
    const dir = bundle({ "server/app/page.js": `const u = process.env["WEB_API_INTERNAL_URL"];` });
    expect(scanBundle(dir)).toEqual({ scanned: 1, found: [] });
  });

  it.each(FORBIDDEN_ENV)("finds %s in a server chunk", (name) => {
    const dir = bundle({ "server/chunks/x.js": `const u = process.env.X_${name}_FILE ?? process.env.${name};` });
    const { found } = scanBundle(dir);
    expect(found.map((f) => f.name)).toContain(name);
  });

  it("finds a name in the standalone output too", () => {
    const dir = bundle({ "standalone/server.js": `process.env.NATS_URL` });
    expect(scanBundle(dir).found).toEqual([{ name: "NATS_URL", file: path.join("standalone", "server.js") }]);
  });

  it("a longer name that contains a forbidden one is not that name", () => {
    const dir = bundle({ "server/chunks/x.js": `process.env.PICTURE_TS_URL_HINT` });
    expect(scanBundle(dir).found).toEqual([]);
  });

  it("reports an empty build as zero files scanned", () => {
    expect(scanBundle(bundle({})).scanned).toBe(0);
  });
});
