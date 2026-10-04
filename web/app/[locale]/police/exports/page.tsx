import { PoliceExports } from "@/src/police/PoliceExports";
import { pageTitle } from "@/src/common/title";

// The police realm's legal exports (WP-23; police.query).
export default function PoliceExportsPage() {
  return <PoliceExports />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.police.nav.exports");
}
