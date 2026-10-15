"use client";

// The police realm's own frame (WP-23; spec 02 F10, 06 §5): a colour band
// that no console page has, so an officer always knows the realm; no
// console navigation; the realm's two pages; the scheme and language
// switches and sign-out, on the kit's tokens like the console's frame.
// The realm never opens the picture WebSocket: every view of the airspace here is a police query, which api checks against the
// account's address list and records with its purpose and case reference
// (docs/runbooks/police-realm.md, "Threats").
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { SessionProvider, useSession } from "@rootxkit/uspace-ui/auth/client";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { SessionDisplay } from "@rootxkit/uspace-ui/model";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { Button, LanguageSwitch } from "@rootxkit/uspace-ui/ui";
import { consoleClient } from "../api/client";
import { BrandMark } from "../shell/brand";
import { SchemeToggle } from "../shell/SchemeToggle";
import { loginPath, policePath } from "../shell/paths";
import type { PoliceConfigResult } from "./config";

const PoliceConfigContext = createContext<PoliceConfigResult | null>(null);

/** The realm's purposes (or the problem with their configuration). */
export function usePoliceConfig(): PoliceConfigResult {
  const v = useContext(PoliceConfigContext);
  if (v === null) throw new Error("usePoliceConfig outside PoliceShell");
  return v;
}

function SignOut() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const { signOut } = useSession();
  const [failed, setFailed] = useState(false);
  return (
    <div className="flex items-center gap-2">
      <Button
        type="button"
        size="sm"
        variant="outline"
        data-testid="sign-out"
        onClick={() => {
          setFailed(false);
          signOut()
            .then(() => router.replace(loginPath(lang)))
            .catch(() => setFailed(true));
        }}
      >
        {t("authority.account.sign_out")}
      </Button>
      {failed && <span role="alert">{t("authority.account.sign_out_failed")}</span>}
    </div>
  );
}

/** Asks api for the session once; a 401 is the sign-in page. */
function SessionCheck() {
  const { lang } = useLang();
  const router = useRouter();
  useEffect(() => {
    consoleClient(
      () => lang,
      () => router.replace(loginPath(lang)),
    )
      .GET("/v1/auth/session")
      .catch(() => undefined);
  }, [lang, router]);
  return null;
}

const ITEMS = [
  { sub: "", labelKey: "authority.police.nav.queries" },
  { sub: "/exports", labelKey: "authority.police.nav.exports" },
] as const;

export function PoliceShell({ session, config, children }: { session: SessionDisplay; config: PoliceConfigResult; children: ReactNode }) {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const { brand } = useTheme();
  return (
    <SessionProvider session={session}>
      <PoliceConfigContext.Provider value={config}>
        <SessionCheck />
        <div className="flex min-h-dvh flex-col bg-background text-foreground" data-realm="police">
          <a
            href="#main"
            className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-card focus:px-3 focus:py-2 focus:text-sm focus:font-semibold focus:text-foreground focus:shadow-overlay"
          >
            {t("authority.skip")}
          </a>
          <header className="sticky top-0 z-30 shadow-panel">
            <div className="police-band flex flex-wrap items-center justify-between gap-x-6 gap-y-2 px-4 py-3 sm:px-6" data-testid="police-band">
              <div className="flex min-w-0 items-center gap-3">
                <span aria-hidden="true" className="inline-flex size-7 shrink-0 items-center justify-center overflow-hidden rounded-md">
                  <BrandMark />
                </span>
                <div className="min-w-0">
                  <p className="m-0 text-base font-bold" data-testid="police-title">
                    {t("authority.police.title", { name: brand.shortName })}
                  </p>
                  <p className="m-0 text-xs opacity-90">{t("authority.police.tagline")}</p>
                </div>
              </div>
              <nav aria-label={t("authority.police.nav.label")} data-testid="police-nav">
                <ul className="m-0 flex list-none flex-wrap gap-1 p-0">
                  {ITEMS.map((i) => {
                    const href = `${policePath(lang)}${i.sub}`;
                    const current = pathname === href;
                    return (
                      <li key={i.sub}>
                        <Link
                          href={href}
                          aria-current={current ? "page" : undefined}
                          className="police-tab inline-flex h-8 items-center rounded-md px-3 text-sm font-semibold no-underline focus-visible:outline-2 focus-visible:outline-offset-2"
                        >
                          {t(i.labelKey)}
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              </nav>
            </div>
            <div className="flex flex-col gap-2 border-b border-border bg-topbar px-4 py-2 sm:px-6 lg:flex-row lg:items-center lg:justify-between lg:gap-6">
              <p className="m-0 min-w-0 flex-1 text-xs text-muted-foreground" data-testid="police-record-notice">
                {t("authority.police.record_notice")}
              </p>
              <div className="flex shrink-0 items-center gap-2">
                <SchemeToggle />
                <LanguageSwitch />
                <SignOut />
              </div>
            </div>
          </header>
          {"problem" in config && (
            <p role="alert" className="m-0 border-b border-border px-4 py-2 text-sm text-[var(--us-danger)] sm:px-6" data-testid="police-config-problem">
              {t("authority.police.config_problem", { problem: config.problem })}
            </p>
          )}
          {"config" in config && config.config.pendingGcaa && (
            <p role="note" className="m-0 border-b border-border px-4 py-1.5 text-xs text-muted-foreground sm:px-6" data-testid="police-pending-gcaa">
              {t("authority.police.pending_gcaa")}
            </p>
          )}
          <main id="main" tabIndex={-1} className="mx-auto flex w-full max-w-[96rem] flex-1 flex-col outline-none sm:px-2">
            {children}
          </main>
          <footer className="flex flex-wrap gap-x-4 gap-y-1 border-t border-border px-4 py-2 text-xs text-muted-foreground sm:px-6">
            <span>{t("authority.footer.operator", { name: brand.name })}</span>
            <span>{t("authority.police.footer")}</span>
          </footer>
        </div>
      </PoliceConfigContext.Provider>
    </SessionProvider>
  );
}
