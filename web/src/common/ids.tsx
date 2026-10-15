"use client";

// An account, client or entity id as the console shows it: api names an
// actor by its id only (SessionInfo.sub, AuditEvent.actor_id, the *_by
// members; no username beside them, and GET /v1/users is not the
// console's), so a long id is shown by its first characters with the
// whole id in the tooltip and to a screen reader. Nothing is resolved or
// guessed; the id is the one api sent.
import { useState } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";

/** Ids at most this long are shown whole. A display bound. */
export const SHORT_ID_MAX = 12;
/** The characters a longer id is shown by. A display bound. */
export const SHORT_ID_KEEP = 8;

/** The id as shown: whole when short, else its first characters and an ellipsis. */
export function shortId(id: string): string {
  return id.length <= SHORT_ID_MAX ? id : `${id.slice(0, SHORT_ID_KEEP)}…`;
}

/** An id, shortened when long, the whole id in its tooltip and for a screen reader. */
export function ShortId({ id, className = "font-mono" }: { id: string; className?: string }) {
  const short = shortId(id);
  if (short === id) {
    return (
      <span className={`whitespace-nowrap ${className}`} data-id={id}>
        {id}
      </span>
    );
  }
  return (
    <span className={`whitespace-nowrap ${className}`} title={id} data-id={id} data-short="true">
      <span aria-hidden="true">{short}</span>
      <span className="sr-only">{id}</span>
    </span>
  );
}

/** A short id with a button that copies the whole one. */
export function CopyId({ id, className }: { id: string; className?: string }) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap">
      <ShortId id={id} {...(className === undefined ? {} : { className })} />
      <button
        type="button"
        className="inline-flex size-6 shrink-0 items-center justify-center rounded text-[var(--us-text-muted)] hover:bg-[var(--us-surface-sunken)] focus-visible:outline-2 focus-visible:outline-[var(--us-focus,currentColor)]"
        aria-label={t(copied ? "authority.id.copied" : "authority.id.copy", { id })}
        title={t(copied ? "authority.id.copied" : "authority.id.copy", { id })}
        data-testid="copy-id"
        onClick={() => {
          navigator.clipboard
            ?.writeText(id)
            .then(() => setCopied(true))
            .catch(() => setCopied(false));
        }}
      >
        <svg aria-hidden="true" viewBox="0 0 16 16" className="size-3.5" fill="none" stroke="currentColor" strokeWidth="1.5">
          <rect x="5" y="5" width="8.5" height="8.5" rx="1.5" />
          <path d="M3 10.5V3.5A1 1 0 0 1 4 2.5h6.5" />
        </svg>
      </button>
    </span>
  );
}
