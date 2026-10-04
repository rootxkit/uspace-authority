"use client";

// The signed-in console's frame: the brand, the navigation by role, the
// account menu with the roles and sign-out, the language switch, and the
// page. The session shown is the cookie's claims decoded without
// verification, for display only (M20); the shell asks api for the
// session once on mount through the BFF, and a 401 from it, like a 4401
// close of the picture, goes to the sign-in page.
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { SessionProvider, useSession } from "@rootxkit/uspace-ui/auth/client";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { SessionDisplay } from "@rootxkit/uspace-ui/model";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@rootxkit/uspace-ui/ui";
import { consoleClient } from "../api/client";
import { LocaleSwitch } from "../components/LocaleSwitch";
import { knownRoles, navFor } from "./nav";
import { loginPath, mapPath } from "./paths";

function AccountMenu() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const { session, signOut } = useSession();
  const [failed, setFailed] = useState(false);
  if (session === null) return null;
  const roles = knownRoles(session.roles);
  return (
    <div className="flex items-center gap-2">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button type="button" variant="outline" size="sm" data-testid="account-menu">
            {t("authority.account.menu")}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>{t(session.realm === "police" ? "authority.realm.police" : "authority.realm.console")}</DropdownMenuLabel>
          <DropdownMenuLabel data-testid="account-roles">
            {roles.length === 0
              ? t("authority.account.no_roles")
              : t("authority.account.roles", { roles: roles.map((r) => t(`authority.role.${r}`)).join(", ") })}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            data-testid="sign-out"
            onSelect={() => {
              setFailed(false);
              signOut()
                .then(() => router.replace(loginPath(lang)))
                .catch(() => setFailed(true));
            }}
          >
            {t("authority.account.sign_out")}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {failed && (
        <span role="alert" className="text-xs text-[var(--us-danger)]">
          {t("authority.account.sign_out_failed")}
        </span>
      )}
    </div>
  );
}

/** Asks api for the session once; a 401 is the sign-in page (the client's onUnauthorized). */
function SessionCheck() {
  const { lang } = useLang();
  const router = useRouter();
  useEffect(() => {
    const client = consoleClient(
      () => lang,
      () => router.replace(loginPath(lang)),
    );
    client.GET("/v1/auth/session").catch(() => undefined);
  }, [lang, router]);
  return null;
}

export function AppShell({ session, children }: { session: SessionDisplay; children: ReactNode }) {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const { brand } = useTheme();
  const items = navFor(session);
  return (
    <SessionProvider session={session}>
      <SessionCheck />
      <div className="flex min-h-full flex-col">
        <a href="#main" className="sr-only focus:not-sr-only">
          {t("authority.skip")}
        </a>
        <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--us-border)] bg-[var(--us-surface-raised)] px-4 py-2">
          <div className="flex items-center gap-3">
            {brand.logoUrl !== null && <img src={brand.logoUrl} alt="" className="h-8 w-auto" />}
            <div>
              <p className="m-0 text-lg font-bold" data-testid="app-title">
                {t("authority.app.title", { name: brand.shortName })}
              </p>
              <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("authority.app.tagline")}</p>
            </div>
          </div>
          <nav aria-label={t("authority.nav.label")} className="flex flex-wrap gap-4 text-sm" data-testid="nav">
            {items.map((i) => {
              const href = `${mapPath(lang)}${i.path}`;
              const current = pathname === href;
              return (
                <Link
                  key={i.path}
                  href={href}
                  aria-current={current ? "page" : undefined}
                  className={current ? "font-bold underline underline-offset-4" : "underline-offset-4 hover:underline"}
                >
                  {t(i.labelKey)}
                </Link>
              );
            })}
          </nav>
          <div className="flex items-center gap-4">
            <LocaleSwitch />
            <AccountMenu />
          </div>
        </header>
        <main id="main" className="flex flex-1 flex-col">
          {children}
        </main>
        <footer className="border-t border-[var(--us-border)] px-4 py-1 text-xs text-[var(--us-text-muted)]">
          <span>{t("authority.footer.operator", { name: brand.name })}</span>
          {brand.contact !== null && <span className="ms-4">{t("authority.footer.contact", { contact: brand.contact })}</span>}
          <span className="ms-4">{t("authority.footer.observer")}</span>
        </footer>
      </div>
    </SessionProvider>
  );
}
