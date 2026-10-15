"use client";

// A page's breadcrumb trail, from where it is: the sidebar group, the
// navigation entry the page belongs to (a link unless it is this page),
// the way back the page names when it is somewhere else again, and the
// page itself. A page that belongs to no console entry (the police realm,
// the public pages) has no trail.
import { usePathname } from "next/navigation";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { Crumb } from "@rootxkit/uspace-ui/ui";
import { NAV_ITEMS, isCurrent, type NavItem } from "./nav";
import { mapPath } from "./paths";

/** The console entry a path belongs to; null for a page outside the console's navigation. */
export function entryFor(lang: string, pathname: string): NavItem | null {
  return NAV_ITEMS.find((i) => isCurrent(i, lang, pathname)) ?? null;
}

export function useTrail(title: string, back?: { href: string; label: string }): Crumb[] | undefined {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const entry = entryFor(lang, pathname);
  if (entry === null) return undefined;
  const entryHref = `${mapPath(lang)}${entry.path}`;
  const crumbs: Crumb[] = [{ label: t(`authority.nav.group.${entry.group}`) }];
  if (entryHref !== pathname) crumbs.push({ label: t(entry.labelKey), href: entryHref });
  if (back !== undefined && back.href !== entryHref && back.href !== pathname) crumbs.push({ label: back.label, href: back.href });
  crumbs.push({ label: title });
  return crumbs;
}
