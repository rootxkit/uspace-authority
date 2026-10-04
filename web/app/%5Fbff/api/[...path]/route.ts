import type { NextRequest } from "next/server";
import { bff } from "@/src/lib/bff/handlers";

export const dynamic = "force-dynamic";

// The methods api's console operations use (src/lib/bff/handlers.ts
// PROXY_ALLOW_PATHS): reads, and since WP-22 the registry, zone, U-space
// and certificate writes. DELETE is not routed: no console operation
// uses it. A method not exported here is Next.js's 405 and never
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
