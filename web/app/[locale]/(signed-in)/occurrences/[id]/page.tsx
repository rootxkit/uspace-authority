import { OccurrenceDetail } from "@/src/oversight/occurrences/Occurrences";
import { pageTitle } from "@/src/common/title";

// One occurrence report (WP-23; incident officer).
export default async function OccurrencePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <OccurrenceDetail id={id} />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.nav.occurrences");
}
