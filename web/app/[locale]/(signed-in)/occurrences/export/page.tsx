import { OccurrenceExport } from "@/src/oversight/occurrences/Occurrences";
import { pageTitle } from "@/src/common/title";

// The de-identified export (WP-23; incident officer).
export default function OccurrenceExportPage() {
  return <OccurrenceExport />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.occurrence_export.title");
}
