"use client";

import { createContext, useCallback, useContext, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { I18nProvider, type Lang } from "@rootxkit/uspace-ui/i18n";
import { ThemeProvider, type Brand, type ColorScheme } from "@rootxkit/uspace-ui/theme";
import { CspNonceProvider } from "@rootxkit/uspace-ui/ui";
import { catalogues } from "../i18n/catalogues";
import type { RuntimeConfig } from "../runtime";
import { langCookie, schemeCookie } from "./langCookie";

const RuntimeContext = createContext<RuntimeConfig | null>(null);

/** The request-time configuration the server handed to the page. */
export function useRuntimeConfig(): RuntimeConfig {
  const v = useContext(RuntimeContext);
  if (v === null) throw new Error("useRuntimeConfig outside Providers");
  return v;
}

/** The same page under `lang`: the language is the path's first segment. */
export function pathInLang(pathname: string, lang: Lang): string {
  return `/${lang}${pathname.replace(/^\/(ka|en)(?=\/|$)/, "")}`;
}

export function Providers(props: { lang: Lang; brand: Brand; scheme: ColorScheme | undefined; nonce: string | undefined; config: RuntimeConfig; children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  // The language switch: remembered in uspace_lang, then the same page in that language.
  const onLangChange = useCallback(
    (l: Lang) => {
      document.cookie = langCookie(l);
      router.push(`${pathInLang(pathname, l)}${window.location.search}`);
    },
    [router, pathname],
  );
  const onSchemeChange = useCallback((s: ColorScheme) => {
    document.cookie = schemeCookie(s);
  }, []);
  return (
    <CspNonceProvider nonce={props.nonce}>
      <RuntimeContext.Provider value={props.config}>
        <ThemeProvider brand={props.brand} scheme={props.scheme} onSchemeChange={onSchemeChange}>
          <I18nProvider lang={props.lang} catalogues={catalogues} onLangChange={onLangChange}>
            {props.children}
          </I18nProvider>
        </ThemeProvider>
      </RuntimeContext.Provider>
    </CspNonceProvider>
  );
}
