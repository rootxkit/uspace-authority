import { createElement, type ReactNode } from "react";
import { fmtTimeUTC, type Lang, type Translate } from "@rootxkit/uspace-ui/i18n";
import { shortId } from "../common/ids";

/** "user-1, 2026-10-02 14:03 UTC": who did it and when, as api recorded it; a long id is shortened (byAt has it whole in the tooltip). */
export function byAtText(t: Translate, lang: Lang, by: string | null | undefined, at: string | null | undefined): string | null {
  if ((by ?? "") === "" && (at ?? "") === "") return null;
  return t("authority.registry.by_at", { by: by === null || by === undefined || by === "" ? t("common.dash") : shortId(by), at: fmtTimeUTC(at ?? null, lang) });
}

/** byAtText, with the whole id in the tooltip when it was shortened. */
export function byAt(t: Translate, lang: Lang, by: string | null | undefined, at: string | null | undefined): ReactNode {
  const text = byAtText(t, lang, by, at);
  if (text === null || by === null || by === undefined || shortId(by) === by) return text;
  return createElement("span", { title: by, "data-id": by }, text);
}
