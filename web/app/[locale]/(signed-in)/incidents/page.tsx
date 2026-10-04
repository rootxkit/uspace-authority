import { IncidentsList } from "@/src/oversight/incidents/IncidentsList";
import { pageTitle } from "@/src/common/title";

// The incidents (WP-23; inspector, incident officer): the case list and
// opening a case.
export default function IncidentsPage() {
  return <IncidentsList />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.nav.incidents");
}
