import { ViolationDetail } from "@/src/oversight/violations/ViolationDetail";
import { pageTitle } from "@/src/common/title";

// One violation (WP-23; inspector): facts, numbers with datums, the
// excerpt in api's segments and holes, the review.
export default async function ViolationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <ViolationDetail id={id} />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.nav.violations");
}
