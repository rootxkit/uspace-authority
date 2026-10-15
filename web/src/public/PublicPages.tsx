"use client";

// The public pages (WP-23; no session): the registration check, the
// public register of certified providers (Art. 18(a)) and the rules, in
// ka and en. Each renders only the members api's public schema has: the
// check is status and end of validity, nothing else (06 §5), and the
// register is holder, code, services, status, validity and limitations.
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, type ReactNode } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { Badge, Button, LanguageSwitch, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../common/Table";
import type { components } from "../api/types";
import { BrandMark } from "../shell/brand";
import { SchemeToggle } from "../shell/SchemeToggle";
import { LoadNotice, ProblemText } from "../common/Problem";
import { PageHeader, TextInput } from "../common/ui";
import { must, useClient, useLoad } from "../common/useApi";
import { loginPath } from "../shell/paths";
import type { Block, Inline } from "./markdown";

type S = components["schemas"];

const PAGES = [
  { sub: "/check", labelKey: "authority.public.nav.check" },
  { sub: "/register", labelKey: "authority.public.nav.register" },
  { sub: "/rules", labelKey: "authority.public.nav.rules" },
] as const;

export function PublicShell({ children }: { children: ReactNode }) {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const { brand } = useTheme();
  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-card focus:px-3 focus:py-2 focus:text-sm focus:font-semibold focus:text-foreground focus:shadow-overlay"
      >
        {t("authority.skip")}
      </a>
      <header className="sticky top-0 z-30 flex min-h-[var(--us-topbar-height)] flex-wrap items-center justify-between gap-x-6 gap-y-2 border-b border-border bg-topbar px-4 py-2 sm:px-6">
        <div className="flex min-w-0 items-center gap-2.5">
          <span aria-hidden="true" className="inline-flex size-7 shrink-0 items-center justify-center overflow-hidden rounded-md">
            <BrandMark />
          </span>
          <p className="m-0 truncate text-sm font-bold">{t("authority.public.title", { name: brand.name })}</p>
        </div>
        <nav aria-label={t("authority.public.nav.label")} data-testid="public-nav">
          <ul className="m-0 flex list-none flex-wrap gap-1 p-0">
            {PAGES.map((p) => {
              const href = `/${lang}${p.sub}`;
              return (
                <li key={p.sub}>
                  <Link
                    href={href}
                    aria-current={pathname === href ? "page" : undefined}
                    className="inline-flex h-8 items-center rounded-md px-3 text-sm font-semibold text-sidebar-text no-underline transition-colors hover:bg-hover focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none aria-[current=page]:bg-accent-soft aria-[current=page]:text-accent-text"
                  >
                    {t(p.labelKey)}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
        <div className="flex items-center gap-2">
          <SchemeToggle />
          <LanguageSwitch />
          <Button asChild size="sm" variant="outline">
            <Link href={loginPath(lang)}>{t("authority.public.sign_in")}</Link>
          </Button>
        </div>
      </header>
      <main id="main" tabIndex={-1} className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-4 py-6 outline-none sm:px-6">
        {children}
      </main>
      <footer className="flex flex-wrap gap-x-4 gap-y-1 border-t border-border px-4 py-2 text-xs text-muted-foreground sm:px-6">
        <span>{t("authority.footer.operator", { name: brand.name })}</span>
        {brand.contact !== null && <span>{t("authority.footer.contact", { contact: brand.contact })}</span>}
      </footer>
    </div>
  );
}

export function RegistrationCheck() {
  const t = useT();
  const { lang } = useLang();
  const client = useClient();
  const [number, setNumber] = useState("");
  const [answer, setAnswer] = useState<S["RegistryCheck"] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <>
      <PageHeader titleKey="authority.public.check.title" introKey="authority.public.check.intro" />
      <form
        className="flex flex-wrap items-end gap-3"
        data-testid="check-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (number.trim() === "") return;
          setBusy(true);
          setError(null);
          setAnswer(null);
          client
            .GET("/v1/registry/check", { params: { query: { number: number.trim() } } })
            .then((r) => setAnswer(must(r)))
            .catch((err: unknown) => {
              if (err instanceof ApiError) setError(err);
            })
            .finally(() => setBusy(false));
        }}
      >
        <TextInput name="number" required maxLength={64} labelKey="authority.public.check.number" hintKey="authority.public.check.number_hint" value={number} onChange={setNumber} testId="check-number" />
        <Button type="submit" disabled={busy} data-testid="check-submit">
          {t("authority.public.check.submit")}
        </Button>
      </form>
      {error !== null && <ProblemText error={error} />}
      {answer !== null && (
        // Only the status and the end of validity: whatever else an answer held is not rendered.
        <div role="status" className="rounded-md border border-[var(--us-border)] p-3" data-testid="check-answer" data-status={answer.status}>
          <p className="m-0 text-lg font-semibold">{t(`authority.public.check.status.${answer.status}`)}</p>
          {answer.valid_until !== undefined && <p className="m-0 text-sm">{t("authority.public.check.valid_until", { at: fmtTimeUTC(answer.valid_until, lang) })}</p>}
          <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("authority.public.check.status_only")}</p>
        </div>
      )}
    </>
  );
}

// The kit's TableCell is whitespace-nowrap (uspace-ui src/ui/table.tsx:92); the
// register's cells hold prose and lists, so they wrap here.
const WRAP = "whitespace-normal";

export function CertificateRegister() {
  const t = useT();
  const { lang } = useLang();
  const { state } = useLoad("register", async (c) => must(await c.GET("/v1/certificates/register")));
  return (
    <>
      <PageHeader titleKey="authority.public.register.title" introKey="authority.public.register.intro" />
      <LoadNotice state={state} />
      {state.kind === "loaded" && (
        <>
          <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("authority.public.register.generated", { at: fmtTimeUTC(state.data.generated_at, lang) })}</p>
          <Table data-testid="register-table">
            <TableCaption>{t("authority.public.register.caption")}</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-40">{t("authority.public.register.holder")}</TableHead>
                <TableHead className="w-28">{t("authority.public.register.code")}</TableHead>
                <TableHead className="min-w-56">{t("authority.public.register.services")}</TableHead>
                <TableHead>{t("authority.public.register.status")}</TableHead>
                <TableHead>{t("authority.public.register.validity")}</TableHead>
                <TableHead>{t("authority.public.register.limitations")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {state.data.certificates.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6}>{t("authority.public.register.empty")}</TableCell>
                </TableRow>
              )}
              {state.data.certificates.map((c) => (
                <TableRow key={c.certificate_id} data-certificate={c.code}>
                  <TableCell className={WRAP}>
                    {c.holder_name}
                    <span className="ms-1 text-xs text-[var(--us-text-muted)]">{t(`authority.public.register.holder.${c.holder}`)}</span>
                  </TableCell>
                  <TableCell className="font-mono">{c.code}</TableCell>
                  <TableCell className={WRAP}>
                    <ul className="m-0 flex list-none flex-wrap gap-1 p-0">
                      {c.services.map((s) => (
                        <li key={s}>
                          <Badge variant="secondary" className="whitespace-normal">
                            {t(`authority.public.register.service.${s}`)}
                          </Badge>
                        </li>
                      ))}
                    </ul>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{t(`authority.public.register.state.${c.status}`)}</Badge>
                  </TableCell>
                  <TableCell className={WRAP}>{t("authority.pack.window_value", { from: fmtTimeUTC(c.valid_from, lang), to: fmtTimeUTC(c.valid_until, lang) })}</TableCell>
                  <TableCell className={WRAP}>{c.limitations.length === 0 ? "—" : c.limitations.join("; ")}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      )}
    </>
  );
}

function InlineView({ nodes }: { nodes: readonly Inline[] }) {
  return (
    <>
      {nodes.map((n, i) => {
        if (n.t === "text") return <span key={i}>{n.v}</span>;
        if (n.t === "code") return <code key={i}>{n.v}</code>;
        if (n.t === "strong")
          return (
            <strong key={i}>
              <InlineView nodes={n.c} />
            </strong>
          );
        if (n.t === "em")
          return (
            <em key={i}>
              <InlineView nodes={n.c} />
            </em>
          );
        return (
          <a key={i} href={n.href} className="underline underline-offset-2" rel="noreferrer">
            <InlineView nodes={n.c} />
          </a>
        );
      })}
    </>
  );
}

/** The configured rules, rendered from the parsed Markdown (no HTML is set). */
export function RulesView({ blocks, problem }: { blocks: readonly Block[] | null; problem: string | null }) {
  const t = useT();
  return (
    <>
      <PageHeader titleKey="authority.public.rules.title" />
      {problem !== null ? (
        <p role="alert" className="m-0 text-[var(--us-danger)]" data-testid="rules-problem">
          {t("authority.public.rules.not_configured", { problem })}
        </p>
      ) : (
        <article className="flex flex-col gap-3" data-testid="rules">
          {(blocks ?? []).map((b, i) => {
            if (b.t === "h") {
              const H = b.level === 1 ? "h2" : b.level === 2 ? "h3" : "h4";
              return (
                <H key={i} className="m-0 font-semibold">
                  <InlineView nodes={b.c} />
                </H>
              );
            }
            if (b.t === "p")
              return (
                <p key={i} className="m-0">
                  <InlineView nodes={b.c} />
                </p>
              );
            const L = b.t === "ul" ? "ul" : "ol";
            return (
              <L key={i} className={b.t === "ul" ? "m-0 list-disc ps-6" : "m-0 list-decimal ps-6"}>
                {b.items.map((it, j) => (
                  <li key={j}>
                    <InlineView nodes={it} />
                  </li>
                ))}
              </L>
            );
          })}
        </article>
      )}
    </>
  );
}
