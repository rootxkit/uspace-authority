import type { ReactNode } from "react";
import { cookies } from "next/headers";
import { RoleGate } from "@/src/shell/RoleGate";
import { displaySession } from "@/src/shell/session";

// The occurrence officer realm (WP-23): for the incident officer alone.
// Another role is told so and its pages read nothing (376/2014 Art.
// 15-16); api refuses the reporter to every other role anyway.
export default async function OccurrencesLayout({ children }: { children: ReactNode }) {
  const session = displaySession(await cookies());
  return (
    <RoleGate roles={session?.roles ?? []} anyOf={["incident_officer"]}>
      {children}
    </RoleGate>
  );
}
