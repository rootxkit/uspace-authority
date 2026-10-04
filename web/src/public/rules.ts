// The rules page's text: one Markdown file per language, named by the
// deployment (WEB_RULES_FILE_KA, WEB_RULES_FILE_EN), read at request time
// and bounded. Unset, unreadable or too large, the page names the
// variable and the problem instead of showing rules of this code's own
// (INV-03: the rules are configuration, never literals). Server code: it
// is imported by the rules page's server component only.
import { open } from "node:fs/promises";
import type { Lang } from "@rootxkit/uspace-ui/i18n";

/** The largest rules file read. A display bound, not a threshold. */
export const RULES_MAX_BYTES = 256 * 1024;

export type RulesText = { markdown: string } | { problem: string };

export function rulesVariable(lang: Lang): string {
  return lang === "ka" ? "WEB_RULES_FILE_KA" : "WEB_RULES_FILE_EN";
}

export async function readRules(lang: Lang, env: Record<string, string | undefined>): Promise<RulesText> {
  const name = rulesVariable(lang);
  const file = env[name];
  if (file === undefined || file.trim() === "") return { problem: `${name} is not set` };
  let h;
  try {
    h = await open(file, "r");
  } catch (err) {
    return { problem: `${name}: ${(err as NodeJS.ErrnoException).code ?? "unreadable"}` };
  }
  try {
    const buf = Buffer.alloc(RULES_MAX_BYTES + 1);
    let n = 0;
    for (;;) {
      const { bytesRead } = await h.read(buf, n, buf.length - n, n);
      if (bytesRead === 0) break;
      n += bytesRead;
      if (n > RULES_MAX_BYTES) return { problem: `${name}: larger than ${RULES_MAX_BYTES} bytes` };
    }
    return { markdown: buf.subarray(0, n).toString("utf8") };
  } catch (err) {
    return { problem: `${name}: ${(err as NodeJS.ErrnoException).code ?? "unreadable"}` };
  } finally {
    await h.close();
  }
}
