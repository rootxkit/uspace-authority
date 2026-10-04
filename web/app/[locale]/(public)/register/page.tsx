import { CertificateRegister } from "@/src/public/PublicPages";
import { pageTitle } from "@/src/common/title";

// The public register of certified providers (WP-23; GET /v1/certificates/register).
export default function RegisterPage() {
  return <CertificateRegister />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.public.nav.register");
}
