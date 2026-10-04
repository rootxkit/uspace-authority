import { PoliceQueries } from "@/src/police/PoliceQueries";
import { pageTitle } from "@/src/common/title";

// The police realm's queries (WP-23; police.query): aircraft in a box,
// an operator, a serial, each with a purpose and a case reference.
export default function PoliceQueriesPage() {
  return <PoliceQueries />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.police.nav.queries");
}
