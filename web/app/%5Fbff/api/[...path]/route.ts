import type { NextRequest } from "next/server";
import { bff } from "@/src/lib/bff/handlers";

export const dynamic = "force-dynamic";

// GET only: every path the proxy reaches in this work package is a read
// (src/lib/bff/handlers.ts PROXY_ALLOW_PATHS). Any other method is
// Next.js's 405 and never reaches api; a page that writes adds its
// method here with its path.
export function GET(req: NextRequest): Promise<Response> {
  return bff().proxy(req);
}
