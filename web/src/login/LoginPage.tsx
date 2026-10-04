"use client";

// /<locale>/login: the kit's LoginForm on the BFF's /_bff/login. The
// password goes once; api answers an MFA challenge (TOTP is mandatory,
// docs/PLAN.md §7), which the BFF seals into an HttpOnly cookie, and the
// form asks for the code. api's refusals are worded in the viewer's
// language by their slug; a rate limit counts down its Retry-After.
import { useMemo } from "react";
import { useRouter } from "next/navigation";
import { BFF_LOGIN_PATH, LoginForm } from "@rootxkit/uspace-ui/auth/client";
import { parseProblem, problemSlug } from "@rootxkit/uspace-ui/api";
import { useLang, useT, type Translate } from "@rootxkit/uspace-ui/i18n";
import { mapPath } from "../shell/paths";

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
  const doFetch = useMemo(() => localisingFetch(t), [t]);
  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-4 p-6">
      <h1 className="m-0 text-xl font-bold">{t("authority.login.title")}</h1>
      <p className="m-0 text-sm text-[var(--us-text-muted)]">{t("authority.login.intro")}</p>
      <LoginForm action={BFF_LOGIN_PATH} fetch={doFetch} onSuccess={() => router.replace(mapPath(lang))} />
    </div>
  );
}
