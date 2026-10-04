import type { ReactNode } from "react";
import { PublicShell } from "@/src/public/PublicPages";

// The public pages (WP-23): no session, no console navigation; ka and en.
export default function PublicLayout({ children }: { children: ReactNode }) {
  return <PublicShell>{children}</PublicShell>;
}
