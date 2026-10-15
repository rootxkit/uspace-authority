"use client";

// The signed-in console's frame, on the kit's AppShell: the sidebar with
// the navigation by role in its groups, the top bar with the system
// name, the feed's pill on a page that has the feed, the scheme toggle,
// the language switch and the user menu with the roles and sign-out. The
// session shown is the cookie's claims decoded without verification, for
// display only (M20); the shell asks api for the session once on mount
// through the BFF, and a 401 from it, like a 4401 close of the picture,
// goes to the sign-in page.
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { SessionProvider, useSession } from "@rootxkit/uspace-ui/auth/client";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { SessionDisplay } from "@rootxkit/uspace-ui/model";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { AppShell as KitShell, DropdownMenuItem, StatusPill, UserMenu, type NavGroup } from "@rootxkit/uspace-ui/ui";
import { consoleClient } from "../api/client";
import { BrandMark } from "./brand";
import { renderLink } from "./link";
import { ShellFeedProvider, useShellFeed } from "./feedPill";
import {
  AuditIcon,
  CertificateIcon,
  IncidentIcon,
  OccurrenceIcon,
  OverviewIcon,
  PictureIcon,
  RegistryIcon,
  SignOutIcon,
  SourceIcon,
  USpaceIcon,
  ViolationIcon,
  ZoneIcon,
} from "./icons";
import { isCurrent, knownRoles, navGroupsFor, type NavIcon } from "./nav";
import { loginPath, mapPath } from "./paths";
import { SchemeToggle } from "./SchemeToggle";
import { shortId } from "../common/ids";

const ICONS: Record<NavIcon, () => ReactNode> = {
  overview: OverviewIcon,
  picture: PictureIcon,
  violations: ViolationIcon,
  incidents: IncidentIcon,
  occurrences: OccurrenceIcon,
  zones: ZoneIcon,
  uspace: USpaceIcon,
  registry: RegistryIcon,
  certificates: CertificateIcon,
  sources: SourceIcon,
  audit: AuditIcon,
};

function AccountMenu() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const { session, signOut } = useSession();
  const [failed, setFailed] = useState(false);
  if (session === null) return null;
  const roles = knownRoles(session.roles);
  return (
    // api's session names the account by its id only (SessionInfo.sub; no
    // username), so the menu shows the id shortened, whole in the tooltip
    // and in the menu.
    <div className="flex items-center gap-2" data-testid="account-menu" title={session.sub} data-id={session.sub}>
      <UserMenu
        name={shortId(session.sub)}
        detail={
          <span className="grid gap-0.5">
            <span className="font-mono break-all" data-testid="account-id">
              {t("authority.account.id", { id: session.sub })}
            </span>
            <span>{t(session.realm === "police" ? "authority.realm.police" : "authority.realm.console")}</span>
            <span data-testid="account-roles">
              {roles.length === 0
                ? t("authority.account.no_roles")
                : t("authority.account.roles", { roles: roles.map((r) => t(`authority.role.${r}`)).join(", ") })}
            </span>
          </span>
        }
      >
        <DropdownMenuItem
          data-testid="sign-out"
          onSelect={() => {
            setFailed(false);
            signOut()
              .then(() => router.replace(loginPath(lang)))
              .catch(() => setFailed(true));
          }}
        >
          <SignOutIcon />
          {t("authority.account.sign_out")}
        </DropdownMenuItem>
      </UserMenu>
      {failed && (
        <span role="alert" className="text-xs text-[var(--us-danger)]">
          {t("authority.account.sign_out_failed")}
        </span>
      )}
    </div>
  );
}

/** Asks api for the session once; a 401 is the sign-in page (the client's onUnauthorized). */
export function SessionCheck() {
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

function FeedStatus() {
  const feed = useShellFeed();
  return feed === null ? null : <StatusPill state={feed.state} ageS={feed.ageS} />;
}

function Frame({ session, children }: { session: SessionDisplay; children: ReactNode }) {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const { brand } = useTheme();
  const nav: NavGroup[] = navGroupsFor(session).map((g) => ({
    id: g.group,
    label: t(`authority.nav.group.${g.group}`),
    items: g.items.map((i) => {
      const Icon = ICONS[i.icon];
      return {
        id: i.path === "" ? "overview" : i.path,
        label: t(i.labelKey),
        href: `${mapPath(lang)}${i.path}`,
        icon: <Icon />,
        active: isCurrent(i, lang, pathname),
      };
    }),
  }));
  return (
    <KitShell
      systemName={
        // Two lines rather than an ellipsis when the brand's name is long.
        <span className="line-clamp-2 block leading-tight whitespace-normal" data-testid="system-name">
          {t("authority.app.title", { name: brand.shortName })}
        </span>
      }
      logo={<BrandMark />}
      nav={nav}
      renderLink={renderLink}
      status={<FeedStatus />}
      actions={<SchemeToggle />}
      user={<AccountMenu />}
      sidebarFooter={
        <div className="grid gap-1">
          <span>{t("authority.footer.observer")}</span>
          <span>{t("authority.footer.operator", { name: brand.name })}</span>
          {brand.contact !== null && <span className="break-words">{t("authority.footer.contact", { contact: brand.contact })}</span>}
        </div>
      }
    >
      <div className="flex min-h-full flex-col">{children}</div>
    </KitShell>
  );
}

export function AppShell({ session, children }: { session: SessionDisplay; children: ReactNode }) {
  return (
    <SessionProvider session={session}>
      <SessionCheck />
      <ShellFeedProvider>
        <Frame session={session}>{children}</Frame>
      </ShellFeedProvider>
    </SessionProvider>
  );
}
