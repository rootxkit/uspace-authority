import type { ReactNode } from "react";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { AppShell } from "@/src/shell/AppShell";
import { loginPath } from "@/src/shell/paths";
import { displaySession } from "@/src/shell/session";

// Every signed-in page. The session cookie's claims are decoded without
// verification to arrange the shell (M20); without a readable session
// the page is the sign-in. api and picture-ws decide every request.
export default async function SignedInLayout({ children, params }: { children: ReactNode; params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  const session = displaySession(await cookies());
  if (session === null) redirect(loginPath(locale));
  return <AppShell session={session}>{children}</AppShell>;
}
