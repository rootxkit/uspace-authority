import { ViolationsList } from "@/src/oversight/violations/ViolationsList";
import { pageTitle } from "@/src/common/title";

// The violations (WP-23; inspector): the list with its filters.
export default function ViolationsPage() {
  return <ViolationsList />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.nav.violations");
}
