// A page's <title> in its language: the page's name and the brand's short
// name (WCAG 2.4.2; the axe check's document-title rule). Server code,
// for a page's generateMetadata.
import type { Metadata } from "next";
import { createTranslator } from "@rootxkit/uspace-ui/i18n";
import { branding } from "../branding";
import { catalogues, isLang } from "../i18n/catalogues";

export async function pageTitle(params: Promise<{ locale: string }>, key: string): Promise<Metadata> {
  const { locale } = await params;
  const t = createTranslator(isLang(locale) ? locale : "en", catalogues);
  return { title: t("authority.title.page", { page: t(key), name: branding(process.env).shortName }) };
}
