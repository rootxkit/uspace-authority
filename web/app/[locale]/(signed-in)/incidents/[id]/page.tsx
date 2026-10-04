import { IncidentDetail } from "@/src/oversight/incidents/IncidentDetail";
import { pageTitle } from "@/src/common/title";

// One case file (WP-23): aircraft, notes, evidence packs.
export default async function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <IncidentDetail id={id} />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.nav.incidents");
}
