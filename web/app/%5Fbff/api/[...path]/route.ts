import type { NextRequest } from "next/server";
import { bff } from "@/src/lib/bff/handlers";

export const dynamic = "force-dynamic";

// The proxy to api: GET for every path of src/lib/bff/handlers.ts
// PROXY_ALLOW_PATHS; POST, PUT and PATCH for the writes of WP-23's pages
// (OVERSIGHT_PROXY_ROUTES names each path's methods, and any other
// method on one of them is refused before api). An unsafe method needs
// the CSRF pair (the kit's check). DELETE is Next.js's 405 and never
// reaches api.
export function GET(req: NextRequest): Promise<Response> {
  return bff().proxy(req);
}

export function POST(req: NextRequest): Promise<Response> {
  return bff().proxy(req);
}

export function PUT(req: NextRequest): Promise<Response> {
  return bff().proxy(req);
}

export function PATCH(req: NextRequest): Promise<Response> {
  return bff().proxy(req);
}
