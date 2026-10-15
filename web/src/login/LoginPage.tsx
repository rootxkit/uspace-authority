"use client";

// /<locale>/login: the kit's LoginForm on the BFF's /_bff/login. The
// password goes once; api answers an MFA challenge (TOTP is mandatory,
// docs/PLAN.md §7), which the BFF seals into an HttpOnly cookie, and the
// form asks for the code. api's refusals are worded in the viewer's
// language by their slug; a rate limit counts down its Retry-After.
import { useMemo } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { BFF_LOGIN_PATH, LoginForm } from "@rootxkit/uspace-ui/auth/client";
import { parseProblem, problemSlug } from "@rootxkit/uspace-ui/api";
import { useLang, useT, type Translate } from "@rootxkit/uspace-ui/i18n";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { LanguageSwitch, PageHeader, Panel } from "@rootxkit/uspace-ui/ui";
import { BrandMark } from "../shell/brand";
import { mapPath } from "../shell/paths";
import { SchemeToggle } from "../shell/SchemeToggle";

/** The sign-in refusals the console words itself (api's and the BFF's slugs). */
export const LOGIN_SLUGS = [
  "invalid_credentials",
  "mfa_refused",
  "rate_limited",
  "mfa_challenge_missing",
  "origin_refused",
  "bff_unavailable",
  "upstream_invalid",
] as const;

/**
 * A fetch for the form that rewrites a problem's `detail` into the
 * viewer's language for the known slugs, keeping api's own detail where
 * the words quote it (a lockout's end); anything else passes as sent.
 */
export function localisingFetch(t: Translate, base: typeof fetch = fetch): typeof fetch {
  return async (input, init) => {
    const res = await base(input, init);
    if (res.ok) return res;
    const problem = await parseProblem(res.clone());
    if (problem === null) return res;
    const slug = problemSlug(problem.type);
    if (slug === null || !(LOGIN_SLUGS as readonly string[]).includes(slug)) return res;
    const headers = new Headers(res.headers);
    headers.delete("Content-Length");
    return new Response(JSON.stringify({ ...problem, detail: t(`authority.login.problem.${slug}`, { detail: problem.detail ?? "" }) }), {
      status: res.status,
      statusText: res.statusText,
      headers,
    });
  };
}

export function LoginPage() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const { brand } = useTheme();
  const doFetch = useMemo(() => localisingFetch(t), [t]);
  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      <header className="flex min-h-[var(--us-topbar-height)] flex-wrap items-center justify-between gap-3 border-b border-border bg-topbar px-4 py-2 sm:px-6">
        <div className="flex min-w-0 items-center gap-2.5">
          <span aria-hidden="true" className="inline-flex size-7 shrink-0 items-center justify-center overflow-hidden rounded-md">
            <BrandMark />
          </span>
          <p className="m-0 truncate text-sm font-bold">{t("authority.app.title", { name: brand.shortName })}</p>
        </div>
        <div className="flex items-center gap-2">
          <SchemeToggle />
          <LanguageSwitch />
        </div>
      </header>
      <main id="main" className="flex flex-1 items-start justify-center px-4 py-10 sm:items-center sm:py-16">
        <div className="grid w-full max-w-md gap-5">
          <PageHeader title={t("authority.login.title")} description={t("authority.login.intro")} />
          <Panel data-testid="login-panel">
            <LoginForm action={BFF_LOGIN_PATH} fetch={doFetch} onSuccess={() => router.replace(mapPath(lang))} />
          </Panel>
          <p className="m-0 text-xs text-muted-foreground">{t("authority.footer.observer")}</p>
          <nav aria-label={t("authority.public.nav.label")}>
            <ul className="m-0 flex list-none flex-wrap gap-x-4 gap-y-1 p-0 text-xs">
              <li>
                <Link className="inline-flex min-h-6 items-center underline underline-offset-2" href={`/${lang}/check`}>
                  {t("authority.public.nav.check")}
                </Link>
              </li>
              <li>
                <Link className="inline-flex min-h-6 items-center underline underline-offset-2" href={`/${lang}/register`}>
                  {t("authority.public.nav.register")}
                </Link>
              </li>
              <li>
                <Link className="inline-flex min-h-6 items-center underline underline-offset-2" href={`/${lang}/rules`}>
                  {t("authority.public.nav.rules")}
                </Link>
              </li>
            </ul>
          </nav>
        </div>
      </main>
      <footer className="flex flex-wrap gap-x-4 gap-y-1 border-t border-border px-4 py-2 text-xs text-muted-foreground sm:px-6">
        <span>{t("authority.footer.operator", { name: brand.name })}</span>
        {brand.contact !== null && <span>{t("authority.footer.contact", { contact: brand.contact })}</span>}
      </footer>
    </div>
  );
}
