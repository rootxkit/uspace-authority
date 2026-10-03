"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LANGS, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { langCookie } from "./langCookie";

/** The same page in the other language; remembers the choice in uspace_lang (langCookie). */
export function LocaleSwitch() {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const rest = pathname.replace(/^\/(ka|en)(?=\/|$)/, "");
  return (
    <nav aria-label={t("authority.locale.label")} className="flex gap-2 text-sm">
      {LANGS.map((l) =>
        l === lang ? (
          <span key={l} aria-current="true" className="font-bold">
            {t(`authority.locale.${l}`)}
          </span>
        ) : (
          <Link
            key={l}
            href={`/${l}${rest}`}
            hrefLang={l}
            lang={l}
            className="underline underline-offset-2"
            onClick={() => {
              document.cookie = langCookie(l);
            }}
          >
            {t(`authority.locale.${l}`)}
          </Link>
        ),
      )}
    </nav>
  );
}
