import { pageTitle } from "@/src/common/title";
import { InspectorMap } from "@/src/picture/InspectorMap";

// The live picture (WP-21): the picture of picture-ws for the viewport,
// the published zones, the sources and the active violations.
export default function PicturePage() {
  return <InspectorMap />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.nav.map");
}
