import { fmtTimeUTC, type Lang, type Translate } from "@rootxkit/uspace-ui/i18n";

/** "user-1, 2026-10-02 14:03 UTC": who did it and when, as api recorded it. */
export function byAt(t: Translate, lang: Lang, by: string | null | undefined, at: string | null | undefined): string | null {
  if ((by ?? "") === "" && (at ?? "") === "") return null;
  return t("authority.registry.by_at", { by: by ?? t("common.dash"), at: fmtTimeUTC(at ?? null, lang) });
}
