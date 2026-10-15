"use client";

// The kit's FeedStatusBar with the degraded part in this system's words:
// the kit names only the degraded keys it knows (manned, dss, ...) and
// shows every other slug "as the server names it", which for picture-ws
// is every slug. Here each known slug is a short label with the server's
// code in its tooltip; an unknown slug is shown as sent, never dropped
// (degraded.ts). The full sentences stay in the degraded banner.
import { useT } from "@rootxkit/uspace-ui/i18n";
import { FeedStatusBar, type FeedStatusInput } from "@rootxkit/uspace-ui/status";
import { DEGRADED_SLUGS, isSlug } from "./degraded";

/** The degraded slugs in the banner's order, known ones first, then any other as sent. */
export function degradedOrder(degraded: readonly string[]): string[] {
  return [...DEGRADED_SLUGS.filter((s) => degraded.includes(s)), ...degraded.filter((s) => !isSlug(s))];
}

export function StatusLine({ status, nowMs }: { status: FeedStatusInput; nowMs: number }) {
  const t = useT();
  const slugs = degradedOrder(status.degraded);
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <FeedStatusBar status={{ ...status, degraded: [] }} nowMs={nowMs} />
      {slugs.length > 0 && (
        <p className="m-0 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs" data-part="degraded" data-testid="status-degraded">
          <span className="font-semibold">{t("authority.degraded.status")}</span>
          {slugs.map((s, i) => (
            <span key={s} title={t("authority.degraded.code", { slug: s })} data-slug={s} className={isSlug(s) ? undefined : "font-mono"}>
              {isSlug(s) ? t(`authority.degraded.label.${s}`) : s}
              {i < slugs.length - 1 && <span aria-hidden="true">;</span>}
            </span>
          ))}
        </p>
      )}
    </div>
  );
}
