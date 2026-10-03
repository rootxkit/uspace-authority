// Branding is configuration (spec 08 Q15, 06 §4): the name, short name,
// logo, contact and accent come from WEB_BRAND_NAME, WEB_BRAND_SHORT_NAME,
// WEB_BRAND_LOGO_URL, WEB_BRAND_CONTACT and WEB_BRAND_ACCENT through the
// kit's brandFromEnv. Without them the name is the role ("U-space"),
// never a real organisation's; an accent that is not a hex colour fails
// the page naming the variable.
import { brandFromEnv, type Brand } from "@rootxkit/uspace-ui/theme";

export const BRAND_PREFIX = "WEB_BRAND_";

let cached: Brand | null = null;

/** The deployment's brand, read once. */
export function branding(env: Record<string, string | undefined>): Brand {
  if (cached === null) cached = brandFromEnv(env, BRAND_PREFIX);
  return cached;
}
