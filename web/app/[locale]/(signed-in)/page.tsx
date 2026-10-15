import { pageTitle } from "@/src/common/title";
import { Overview } from "@/src/overview/Overview";

// The console's home: the overview of the live picture and each role's
// work queues, from what the console already reads.
export default function OverviewPage() {
  return <Overview />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.nav.overview");
}
