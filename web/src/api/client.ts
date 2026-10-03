// The console's only way to reach api: the kit's typed client on the
// BFF's proxy (/_bff/api/*). The BFF holds the session in its HttpOnly
// cookie and forwards it as the bearer; unsafe methods carry the
// double-submit X-CSRF-Token. The proxy reaches the paths of
// src/lib/bff/handlers.ts PROXY_ALLOW_PATHS and nothing else.
import { BFF_API_PREFIX, csrfToken } from "@rootxkit/uspace-ui/auth/client";
import { createClient } from "@rootxkit/uspace-ui/api";
import type { Lang } from "@rootxkit/uspace-ui/i18n";
import type { paths } from "./types";

export function consoleClient(lang: () => Lang, onUnauthorized: () => void) {
  return createClient<paths>({
    baseUrl: BFF_API_PREFIX,
    csrfToken: () => csrfToken(),
    onUnauthorized,
    lang,
  });
}

export type ConsoleClient = ReturnType<typeof consoleClient>;
