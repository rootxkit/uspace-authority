import type { ReactNode } from "react";
import type { Metadata } from "next";
import { cookies, headers } from "next/headers";
import { notFound } from "next/navigation";
import { CSP_NONCE_HEADER } from "@rootxkit/uspace-ui/auth/server";
import { fontClassName } from "@rootxkit/uspace-ui/fonts";
import { createTranslator } from "@rootxkit/uspace-ui/i18n";
import { SCHEME_COOKIE, parseScheme, schemeAttribute } from "@rootxkit/uspace-ui/theme";
import { Providers } from "@/src/components/Providers";
import { branding } from "@/src/branding";
import { catalogues, isLang } from "@/src/i18n/catalogues";
import { runtimeConfig } from "@/src/runtime";
import "../globals.css";

export const dynamic = "force-dynamic";

// Every page has a title (WCAG 2.4.2): the console's name in the page's language.
export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  if (!isLang(locale)) return {};
  return { title: createTranslator(locale, catalogues)("authority.app.title", { name: branding(process.env).shortName }) };
}

export default async function LocaleLayout({ children, params }: { children: ReactNode; params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  if (!isLang(locale)) notFound();
  const nonce = (await headers()).get(CSP_NONCE_HEADER) ?? undefined;
  // A scheme chosen with the toggle is painted from the first byte; none
  // (or system) leaves data-theme off and the kit's tokens follow the
  // browser's preference.
  const scheme = parseScheme((await cookies()).get(SCHEME_COOKIE)?.value) ?? undefined;
  return (
    <html lang={locale} className={fontClassName} data-theme={schemeAttribute(scheme)} suppressHydrationWarning>
      <body className="font-sans antialiased">
        <Providers lang={locale} brand={branding(process.env)} scheme={scheme} nonce={nonce} config={runtimeConfig(process.env)}>
          {children}
        </Providers>
      </body>
    </html>
  );
}
