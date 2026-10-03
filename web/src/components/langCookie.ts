import { LANG_COOKIE, type Lang } from "@rootxkit/uspace-ui/i18n";

/** A year: the choice is remembered until it is changed. A display preference, not a threshold. */
const LANG_COOKIE_MAX_AGE_S = 31_536_000;

/**
 * The `uspace_lang` cookie the language switch sets: readable by the page
 * (a preference, not a credential), Secure like every cookie of this
 * origin, Lax so a link from elsewhere still opens in the chosen language.
 */
export function langCookie(lang: Lang): string {
  return `${LANG_COOKIE}=${lang}; Path=/; Max-Age=${LANG_COOKIE_MAX_AGE_S}; SameSite=Lax; Secure`;
}
