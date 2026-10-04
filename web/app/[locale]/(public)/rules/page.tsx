import { notFound } from "next/navigation";
import { isLang } from "@/src/i18n/catalogues";
import { parseMarkdown } from "@/src/public/markdown";
import { RulesView } from "@/src/public/PublicPages";
import { readRules } from "@/src/public/rules";
import { pageTitle } from "@/src/common/title";

export const dynamic = "force-dynamic";

// The rules page (WP-23): the deployment's Markdown for the page's
// language (WEB_RULES_FILE_KA, WEB_RULES_FILE_EN), read at request time.
export default async function RulesPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  if (!isLang(locale)) notFound();
  const text = await readRules(locale, process.env);
  return "markdown" in text ? <RulesView blocks={parseMarkdown(text.markdown)} problem={null} /> : <RulesView blocks={null} problem={text.problem} />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.public.nav.rules");
}
