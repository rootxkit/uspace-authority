// The app's own ka/en catalogues, handed to the kit's I18nProvider (which
// puts them ahead of the kit's). Every display string in app/ and src/
// comes from here or from the kit (CLAUDE.md rule 12;
// test/no-literals.test.ts). The registry, zone, U-space and
// certificate pages (WP-22) keep theirs in authoring.{en,ka}.json and
// WP-23's pages in oversight.{ka,en}.json, merged here; a key is in
// exactly one file of a language (catalogue.test.ts).
import type { Catalogues, Lang } from "@rootxkit/uspace-ui/i18n";
import authoringEn from "./authoring.en.json";
import authoringKa from "./authoring.ka.json";
import enBase from "./en.json";
import kaBase from "./ka.json";
import enOversight from "./oversight.en.json";
import kaOversight from "./oversight.ka.json";

export const en: Readonly<Record<string, string>> = { ...enBase, ...enOversight, ...authoringEn };
export const ka: Readonly<Record<string, string>> = { ...kaBase, ...kaOversight, ...authoringKa };

export const catalogues: Catalogues = { ka, en };

export type AppKey = keyof typeof enBase | keyof typeof enOversight | keyof typeof authoringEn;

export function isLang(v: string): v is Lang {
  return v === "ka" || v === "en";
}
