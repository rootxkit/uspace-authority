import { RegistrationCheck } from "@/src/public/PublicPages";
import { pageTitle } from "@/src/common/title";

// The public registration check: status only (WP-23; GET /v1/registry/check).
export default function CheckPage() {
  return <RegistrationCheck />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.public.nav.check");
}
