// The lint rules on the fixtures (E-01): each forbidden file fails with
// the rule it breaks, and its twin that differs in one thing passes;
// then the real BFF and pages pass under the same configuration.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("the project configuration on the fixtures", () => {
  // ignore: false lints the fixtures the configuration otherwise skips.
  const eslint = new ESLint({ cwd: webRoot, ignore: false });

  async function ruleIds(file: string): Promise<string[]> {
    const [result] = await eslint.lintFiles([path.join(webRoot, "eslint-rules/fixtures", file)]);
    return (result?.messages ?? []).map((m) => m.ruleId ?? `fatal: ${m.message}`);
  }

  it("a module importing @turf/area fails no-restricted-imports (and the kit's rule)", async () => {
    const ids = await ruleIds("src/geometry.ts");
    expect(ids).toContain("no-restricted-imports");
    expect(ids).toContain("uspace-ui/no-geometry-imports");
  });

  it("its twin importing the kit passes", async () => {
    expect(await ruleIds("src/twin.ts")).toEqual([]);
  });

  it("a module importing jose fails no-restricted-imports", async () => {
    expect(await ruleIds("src/jwt.ts")).toContain("no-restricted-imports");
  });

  it("a module importing nats and pg fails twice", async () => {
    const ids = await ruleIds("src/server-clients.ts");
    expect(ids.filter((i) => i === "no-restricted-imports")).toHaveLength(2);
  });

  it("a route.ts outside app/%5Fbff fails no-server-routes", async () => {
    expect(await ruleIds("app/api/picture/route.ts")).toContain("authority/no-server-routes");
  });

  it("display text in JSX fails no-jsx-literals, its catalogue twin passes", async () => {
    expect((await ruleIds("src/literals.tsx")).filter((i) => i === "authority/no-jsx-literals")).toHaveLength(2);
    expect(await ruleIds("src/twin-literals.tsx")).toEqual([]);
  });

  it("the real BFF, pages and components pass", async () => {
    const results = await eslint.lintFiles([path.join(webRoot, "app"), path.join(webRoot, "src")]);
    expect(results.length).toBeGreaterThan(20);
    expect(results.flatMap((r) => r.messages.map((m) => `${path.relative(webRoot, r.filePath)}: ${m.ruleId} ${m.message}`))).toEqual([]);
  });
}, 120_000);
