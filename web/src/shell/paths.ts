/** The sign-in page of `lang`. */
export function loginPath(lang: string): string {
  return `/${lang}/login`;
}

/** The inspector map of `lang`. */
export function mapPath(lang: string): string {
  return `/${lang}`;
}

/** The police realm's home of `lang` (WP-23): its own layout, no console navigation. */
export function policePath(lang: string): string {
  return `/${lang}/police`;
}

/** A console page of `lang` under the shell, `sub` starting with "/". */
export function consolePath(lang: string, sub: string): string {
  return `/${lang}${sub}`;
}
