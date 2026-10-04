// The app's own ka/en catalogues, handed to the kit's I18nProvider (which
// puts them ahead of the kit's). Every display string in app/ and src/
// comes from here or from the kit (CLAUDE.md rule 12;
// test/no-literals.test.ts). WP-23's pages keep their strings in
// oversight.{ka,en}.json, merged here; a key is in exactly one file.
import type { Catalogues, Lang } from "@rootxkit/uspace-ui/i18n";
import enBase from "./en.json";
import kaBase from "./ka.json";
import enOversight from "./oversight.en.json";
import kaOversight from "./oversight.ka.json";

export const en: Readonly<Record<string, string>> = { ...enBase, ...enOversight };
export const ka: Readonly<Record<string, string>> = { ...kaBase, ...kaOversight };

export const catalogues: Catalogues = { ka, en };

export type AppKey = keyof typeof enBase | keyof typeof enOversight;

export function isLang(v: string): v is Lang {
  return v === "ka" || v === "en";
}
