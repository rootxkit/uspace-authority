import { Audit } from "@/src/oversight/audit/Audit";
import { pageTitle } from "@/src/common/title";

// The audit log, the chain verification and the DPO report (WP-23; admin, auditor).
export default function AuditPage() {
  return <Audit />;
}

export function generateMetadata({ params }: { params: Promise<{ locale: string }> }) {
  return pageTitle(params, "authority.nav.audit");
}
