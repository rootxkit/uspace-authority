"use client";

// The published zones for the inspector map, read once per language
// through the BFF (GET /v1/zones?state=published, page by page). The read
// is bounded: at most ZONE_PAGES_MAX pages of ZONE_PAGE_LIMIT; past it
// the map says the list is incomplete. A refusal (a role api does not
// serve the zones to) or a failure is said, never shown as "no zones".
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError } from "@rootxkit/uspace-ui/api";
import type { Lang } from "@rootxkit/uspace-ui/i18n";
import type { ZoneView } from "@rootxkit/uspace-ui/model";
import { consoleClient } from "../api/client";
import { loginPath } from "../shell/paths";
import { adaptZone, type ZoneVersion } from "./adapt";

/** api's page maximum (api/openapi.yaml listZones `limit`). */
export const ZONE_PAGE_LIMIT = 500;
/** The read's bound: 20 pages of 500 zones. A display bound, not a threshold. */
export const ZONE_PAGES_MAX = 20;

export type ZonesState =
  | { kind: "loading" }
  | { kind: "loaded"; zones: ZoneView[]; undrawn: string[]; truncated: boolean }
  | { kind: "refused"; status: number }
  | { kind: "failed" };

export function useZones(lang: Lang): ZonesState {
  const router = useRouter();
  const [state, setState] = useState<ZonesState>({ kind: "loading" });
  useEffect(() => {
    let live = true;
    const client = consoleClient(
      () => lang,
      () => router.replace(loginPath(lang)),
    );
    (async () => {
      const all: ZoneVersion[] = [];
      let after: string | undefined;
      let pages = 0;
      for (;;) {
        const { data } = await client.GET("/v1/zones", {
          params: { query: { state: "published", limit: ZONE_PAGE_LIMIT, ...(after === undefined ? {} : { after }) } },
        });
        pages++;
        all.push(...(data?.zones ?? []));
        after = data?.next_after;
        if (after === undefined || pages >= ZONE_PAGES_MAX) break;
      }
      const zones: ZoneView[] = [];
      const undrawn: string[] = [];
      for (const z of all) {
        const a = adaptZone(z, lang);
        if (a.drawn) zones.push(a.view);
        else undrawn.push(a.identifier);
      }
      if (live) setState({ kind: "loaded", zones, undrawn, truncated: after !== undefined });
    })().catch((err: unknown) => {
      if (!live) return;
      if (err instanceof ApiError && err.status !== 401) setState({ kind: "refused", status: err.status });
      else if (!(err instanceof ApiError)) setState({ kind: "failed" });
    });
    return () => {
      live = false;
    };
  }, [lang, router]);
  return state;
}
