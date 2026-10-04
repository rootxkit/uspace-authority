import { OccurrenceQueue } from "@/src/oversight/occurrences/Occurrences";
import { pageTitle } from "@/src/common/title";

// The intake queue with the 72 h flag (WP-23; incident officer).
export default function OccurrencesPage() {
  return <OccurrenceQueue />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.nav.occurrences");
}
