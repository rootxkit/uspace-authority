"use client";

// A page for some roles only: for any other session it says so and reads
// nothing. A courtesy and a boundary of the console's own flows, never a
// grant: api refuses what a role may not read whatever this renders.
import type { ReactNode } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";

export function RoleGate({ roles, anyOf, children }: { roles: readonly string[]; anyOf: readonly string[]; children: ReactNode }) {
  const t = useT();
  if (anyOf.some((r) => roles.includes(r))) return <>{children}</>;
  return (
    <div className="p-4" role="alert" data-testid="role-refused">
      <p className="m-0 font-semibold">{t("authority.gate.title")}</p>
      <p className="m-0 text-sm">{t("authority.gate.body", { roles: anyOf.map((r) => t(`authority.role.${r}`)).join(", ") })}</p>
    </div>
  );
}
