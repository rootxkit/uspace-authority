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
import { Badge, Button, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { Table } from "../common/Table";
import type { components } from "../api/types";
import { LocaleSwitch } from "../components/LocaleSwitch";
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
    <div className="flex min-h-full flex-col">
      <a href="#main" className="sr-only focus:not-sr-only">
        {t("authority.skip")}
      </a>
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--us-border)] bg-[var(--us-surface-raised)] px-4 py-2">
        <p className="m-0 text-lg font-bold">{t("authority.public.title", { name: brand.name })}</p>
        <nav aria-label={t("authority.public.nav.label")} className="flex flex-wrap gap-4 text-sm" data-testid="public-nav">
          {PAGES.map((p) => {
            const href = `/${lang}${p.sub}`;
            return (
              <Link key={p.sub} href={href} aria-current={pathname === href ? "page" : undefined} className={pathname === href ? "font-bold underline underline-offset-4" : "underline-offset-4 hover:underline"}>
                {t(p.labelKey)}
              </Link>
            );
          })}
        </nav>
        <div className="flex items-center gap-4">
          <LocaleSwitch />
          <Link className="text-sm underline underline-offset-2" href={loginPath(lang)}>
            {t("authority.public.sign_in")}
          </Link>
        </div>
      </header>
      <main id="main" className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-4 p-4">
        {children}
      </main>
      <footer className="border-t border-[var(--us-border)] px-4 py-1 text-xs text-[var(--us-text-muted)]">
        <span>{t("authority.footer.operator", { name: brand.name })}</span>
        {brand.contact !== null && <span className="ms-4">{t("authority.footer.contact", { contact: brand.contact })}</span>}
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
                <TableHead>{t("authority.public.register.holder")}</TableHead>
                <TableHead>{t("authority.public.register.code")}</TableHead>
                <TableHead>{t("authority.public.register.services")}</TableHead>
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
                  <TableCell>
                    {c.holder_name}
                    <span className="ms-1 text-xs text-[var(--us-text-muted)]">{t(`authority.public.register.holder.${c.holder}`)}</span>
                  </TableCell>
                  <TableCell className="font-mono">{c.code}</TableCell>
                  <TableCell>{c.services.map((s) => t(`authority.public.register.service.${s}`)).join(", ")}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{t(`authority.public.register.state.${c.status}`)}</Badge>
                  </TableCell>
                  <TableCell>{t("authority.pack.window_value", { from: fmtTimeUTC(c.valid_from, lang), to: fmtTimeUTC(c.valid_until, lang) })}</TableCell>
                  <TableCell>{c.limitations.length === 0 ? "—" : c.limitations.join("; ")}</TableCell>
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
