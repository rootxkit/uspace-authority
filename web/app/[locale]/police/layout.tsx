import type { ReactNode } from "react";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { policeConfigFromEnv } from "@/src/police/config";
import { PoliceShell } from "@/src/police/PoliceShell";
import { loginPath, mapPath } from "@/src/shell/paths";
import { displaySession } from "@/src/shell/session";
import "@/src/police/police.css";

// The police realm (WP-23): its own layout, no console navigation. The
// session cookie's claims are decoded without verification to choose the
// layout (M20): no session is the sign-in, a console session is the
// console. The purposes are read at request time (WEB_POLICE_PURPOSES,
// WEB_POLICE_PII_PURPOSES; defaults pending GCAA). api decides every
// query, and refuses a console session on each one.
export default async function PoliceLayout({ children, params }: { children: ReactNode; params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  const session = displaySession(await cookies());
  if (session === null) redirect(loginPath(locale));
  if (session.realm !== "police") redirect(mapPath(locale));
  return (
    <PoliceShell session={session} config={policeConfigFromEnv(process.env)}>
      {children}
    </PoliceShell>
  );
}
