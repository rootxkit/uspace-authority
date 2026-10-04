// The app's own ka/en catalogues, handed to the kit's I18nProvider (which
// puts them ahead of the kit's). Every display string in app/ and src/
// comes from here or from the kit (CLAUDE.md rule 12;
// test/no-literals.test.ts). The registry, zone, U-space and
// certificate pages (WP-22) keep theirs in authoring.{en,ka}.json; the
// two files of a language never hold the same key (catalogue.test.ts).
import type { Catalogues, Lang } from "@rootxkit/uspace-ui/i18n";
import authoringEn from "./authoring.en.json";
import authoringKa from "./authoring.ka.json";
import en from "./en.json";
import ka from "./ka.json";

export const catalogues: Catalogues = { ka: { ...ka, ...authoringKa }, en: { ...en, ...authoringEn } };

export type AppKey = keyof typeof en | keyof typeof authoringEn;

export function isLang(v: string): v is Lang {
  return v === "ka" || v === "en";
}
