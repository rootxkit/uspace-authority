"use client";

// The police realm's own frame (WP-23; spec 02 F10, 06 §5): a colour band
// that no console page has, so an officer always knows the realm; no
// console navigation; the realm's two pages; the language switch and
// sign-out. The realm never opens the picture WebSocket: every view of
// the airspace here is a police query, which api checks against the
// account's address list and records with its purpose and case reference
// (docs/runbooks/police-realm.md, "Threats").
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { SessionProvider, useSession } from "@rootxkit/uspace-ui/auth/client";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { SessionDisplay } from "@rootxkit/uspace-ui/model";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { Button } from "@rootxkit/uspace-ui/ui";
import { consoleClient } from "../api/client";
import { LocaleSwitch } from "../components/LocaleSwitch";
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
        <div className="flex min-h-full flex-col" data-realm="police">
          <a href="#main" className="sr-only focus:not-sr-only">
            {t("authority.skip")}
          </a>
          <header className="police-band flex flex-wrap items-center justify-between gap-4 px-4 py-2" data-testid="police-band">
            <div>
              <p className="m-0 text-lg font-bold" data-testid="police-title">
                {t("authority.police.title", { name: brand.shortName })}
              </p>
              <p className="m-0 text-xs">{t("authority.police.tagline")}</p>
            </div>
            <nav aria-label={t("authority.police.nav.label")} className="flex flex-wrap gap-4 text-sm" data-testid="police-nav">
              {ITEMS.map((i) => {
                const href = `${policePath(lang)}${i.sub}`;
                const current = pathname === href;
                return (
                  <Link key={i.sub} href={href} aria-current={current ? "page" : undefined} className={current ? "font-bold underline underline-offset-4" : "underline-offset-4 hover:underline"}>
                    {t(i.labelKey)}
                  </Link>
                );
              })}
            </nav>
            <div className="flex items-center gap-4">
              <LocaleSwitch />
              <SignOut />
            </div>
          </header>
          <p className="m-0 border-b border-[var(--us-border)] px-4 py-1 text-xs" data-testid="police-record-notice">
            {t("authority.police.record_notice")}
          </p>
          {"problem" in config && (
            <p role="alert" className="m-0 px-4 py-2 text-sm text-[var(--us-danger)]" data-testid="police-config-problem">
              {t("authority.police.config_problem", { problem: config.problem })}
            </p>
          )}
          {"config" in config && config.config.pendingGcaa && (
            <p role="note" className="m-0 px-4 py-1 text-xs text-[var(--us-text-muted)]" data-testid="police-pending-gcaa">
              {t("authority.police.pending_gcaa")}
            </p>
          )}
          <main id="main" className="flex flex-1 flex-col">
            {children}
          </main>
          <footer className="border-t border-[var(--us-border)] px-4 py-1 text-xs text-[var(--us-text-muted)]">
            <span>{t("authority.footer.operator", { name: brand.name })}</span>
            <span className="ms-4">{t("authority.police.footer")}</span>
          </footer>
        </div>
      </PoliceConfigContext.Provider>
    </SessionProvider>
  );
}
