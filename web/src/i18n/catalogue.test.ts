import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import authoringEn from "./authoring.en.json";
import authoringKa from "./authoring.ka.json";
import { en, ka } from "./catalogues";
import enBase from "./en.json";
import kaBase from "./ka.json";
import enOversight from "./oversight.en.json";
import kaOversight from "./oversight.ka.json";

const GEORGIAN = /[Ⴀ-ჿᲐ-Ჿⴀ-⴯]/u;
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) return name === "generated" ? [] : sources(p);
    return /\.tsx?$/.test(name) && !name.endsWith(".test.ts") ? [p] : [];
  });
}

describe("catalogues", () => {
  it("ka and en hold the same keys", () => {
    expect(Object.keys(ka).sort()).toEqual(Object.keys(en).sort());
    expect(Object.keys(authoringKa).sort()).toEqual(Object.keys(authoringEn).sort());
  });

  it("the two files of a language never hold the same key (one would hide the other)", () => {
    expect(Object.keys(authoringEn).filter((k) => k in enBase || k in enOversight)).toEqual([]);
    expect(Object.keys(authoringKa).filter((k) => k in kaBase || k in kaOversight)).toEqual([]);
    expect(Object.keys(en)).toHaveLength(Object.keys(enBase).length + Object.keys(enOversight).length + Object.keys(authoringEn).length);
  });

  it("a key is in one file of a language only, never in both", () => {
    expect(Object.keys(enOversight).filter((k) => k in enBase)).toEqual([]);
    expect(Object.keys(kaOversight).filter((k) => k in kaBase)).toEqual([]);
  });

  it("a key missing from one catalogue is found", () => {
    const short: Record<string, string> = { ...ka };
    delete short["authority.nav.map"];
    expect(Object.keys(short).sort()).not.toEqual(Object.keys(en).sort());
  });

  it("no value is empty, and the placeholders match between the languages", () => {
    const vars = (s: string) => [...s.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1]).sort();
    for (const [k, v] of Object.entries(en)) {
      expect(v.trim(), k).not.toBe("");
      expect(vars((ka as Record<string, string>)[k] ?? ""), k).toEqual(vars(v));
    }
  });

  it("the Georgian catalogue is Georgian", () => {
    expect(ka["authority.login.title"]).toMatch(GEORGIAN);
    expect(en["authority.login.title"]).not.toMatch(GEORGIAN);
    expect(ka["authority.registry.save"]).toMatch(GEORGIAN);
    expect(en["authority.registry.save"]).not.toMatch(GEORGIAN);
  });

  it("every literal authority.* key the code names exists", () => {
    const named = new Set<string>();
    for (const f of [...sources(path.join(web, "src")), ...sources(path.join(web, "app"))]) {
      for (const m of readFileSync(f, "utf8").matchAll(/"(authority\.[a-z0-9_.]+)"/g)) named.add(m[1] ?? "");
    }
    expect(named.size).toBeGreaterThan(30);
    expect([...named].filter((k) => !(k in en))).toEqual([]);
  });
});
