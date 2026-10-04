import { Sources } from "@/src/oversight/sources/Sources";
import { pageTitle } from "@/src/common/title";

// The sources and their switches (WP-23; admin).
export default function SourcesPage() {
  return <Sources />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.nav.sources");
}
