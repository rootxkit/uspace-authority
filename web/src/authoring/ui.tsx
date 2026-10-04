"use client";

// The pieces every authoring page shares: the page heading, what api
// refused or failed to answer (in words, with its field problems by
// path), a list of facts, the role courtesy, and an act that confirms
// its exact effect before it runs.
import Link from "next/link";
import { useState, type ReactNode } from "react";
import { ApiError } from "@rootxkit/uspace-ui/api";
import { RequireRole, useSession } from "@rootxkit/uspace-ui/auth/client";
import { ConfirmDialog, FieldErrors } from "@rootxkit/uspace-ui/form";
import { fmtTimeUTC, useLang, useT, type Vars } from "@rootxkit/uspace-ui/i18n";
import { Button, Skeleton } from "@rootxkit/uspace-ui/ui";
import type { Role } from "../shell/nav";
import { outcomeOf, type Load } from "./api";

/** A page's heading, the way back, and its actions. */
export function PageHeader(props: { titleKey: string; vars?: Vars; back?: { href: string; labelKey: string }; children?: ReactNode }) {
  const t = useT();
  return (
    <header className="flex flex-wrap items-end justify-between gap-3 border-b border-[var(--us-border)] px-4 py-3">
      <div className="flex flex-col gap-1">
        {props.back !== undefined && (
          <Link href={props.back.href} className="text-sm underline underline-offset-2">
            {t(props.back.labelKey)}
          </Link>
        )}
        <h1 className="m-0 text-xl font-bold">{t(props.titleKey, props.vars)}</h1>
      </div>
      {props.children !== undefined && <div className="flex flex-wrap items-center gap-2">{props.children}</div>}
    </header>
  );
}

/** api's refusal (status, title, detail, every field problem) or the failure to reach it. */
export function ProblemNotice({ error, testId = "problem" }: { error: ApiError | "failed"; testId?: string }) {
  const t = useT();
  if (error === "failed") {
    return (
      <div role="alert" className="rounded border border-[var(--us-danger)] p-3 text-sm" data-testid={testId} data-status="failed">
        {t("authority.act.failed")}
      </div>
    );
  }
  const p = error.problem;
  return (
    <div role="alert" className="flex flex-col gap-1 rounded border border-[var(--us-danger)] p-3 text-sm" data-testid={testId} data-status={error.status} data-slug={error.slug ?? ""}>
      <p className="m-0 font-semibold">{t("authority.act.refused", { status: error.status, title: p?.title ?? "" })}</p>
      {p?.detail !== null && p?.detail !== undefined && p.detail !== "" && <p className="m-0">{p.detail}</p>}
      {p !== null && p.errors.length > 0 && <FieldErrors errors={p.errors} truncated={p.truncated === true} />}
    </div>
  );
}

/** A read in progress, refused or failed; `children` gets the data once loaded. */
export function Loaded<T>({ state, children, testId }: { state: Load<T>; children: (data: T) => ReactNode; testId?: string }) {
  const t = useT();
  if (state.kind === "loading") {
    return (
      <div className="flex flex-col gap-2 p-4" aria-busy="true" data-testid={testId === undefined ? undefined : `${testId}-loading`}>
        <span className="sr-only">{t("authority.act.loading")}</span>
        <Skeleton className="h-6 w-1/2" />
        <Skeleton className="h-6 w-1/3" />
      </div>
    );
  }
  if (state.kind === "refused") return <ProblemNotice error={state.error} testId={testId === undefined ? "problem" : `${testId}-problem`} />;
  if (state.kind === "failed") return <ProblemNotice error="failed" testId={testId === undefined ? "problem" : `${testId}-problem`} />;
  return <>{children(state.data)}</>;
}

/** Facts as a description list: a label key and its value; a missing value is a dash. */
export function Facts({ items, testId }: { items: readonly (readonly [string, ReactNode])[]; testId?: string }) {
  const t = useT();
  return (
    <dl className="m-0 grid grid-cols-[minmax(10rem,auto)_1fr] gap-x-4 gap-y-1 text-sm" data-testid={testId}>
      {items.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-[var(--us-text-muted)]">{t(k)}</dt>
          <dd className="m-0 break-words">{v === null || v === undefined || v === "" ? t("common.dash") : v}</dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * Shown when the session holds one of `roles` (the operation's x-roles).
 * A courtesy to the layout, never a control: api refuses whatever this
 * shows (the kit's RequireRole).
 */
export function Can({ roles, children, fallback }: { roles: readonly Role[]; children: ReactNode; fallback?: ReactNode }) {
  return (
    <RequireRole anyOf={[...roles]} fallback={fallback}>
      {children}
    </RequireRole>
  );
}

/** True when the session holds one of `roles` (display only). */
export function useHasRole(roles: readonly Role[]): boolean {
  const { session } = useSession();
  return session !== null && roles.some((r) => session.roles.includes(r));
}

export interface ActProps<T> {
  /** The button's label. */
  labelKey: string;
  /** The dialog's title and its exact effect. */
  titleKey: string;
  bodyKey: string;
  vars?: Vars;
  /** Ask for a reason (api's minLength) and pass it to `run`. */
  reason?: { minLength: number };
  destructive?: boolean;
  /** The call; resolves with what api answered. */
  run(reason: string | undefined): Promise<T>;
  /** After api accepted it. */
  onDone?(result: T): void;
  testId: string;
  disabled?: boolean;
}

/**
 * A button that asks before it acts: the dialog states the effect in
 * words (the count, the version, the target), takes the reason where api
 * requires one, then calls api once. What api refused is shown beside
 * the button with its problem; nothing is retried.
 */
export function Act<T>(props: ActProps<T>) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | "failed" | null>(null);
  return (
    <div className="flex flex-col gap-1">
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        titleKey={props.titleKey}
        bodyKey={props.bodyKey}
        {...(props.vars === undefined ? {} : { vars: props.vars })}
        {...(props.reason === undefined ? {} : { reason: { required: true as const, minLength: props.reason.minLength } })}
        {...(props.destructive === true ? { destructive: true } : {})}
        onConfirm={(reason) => {
          setOpen(false);
          setBusy(true);
          setError(null);
          props
            .run(reason)
            .then((r) => props.onDone?.(r))
            .catch((err: unknown) => {
              const o = outcomeOf(err);
              setError(o.kind === "refused" ? o.error : "failed");
            })
            .finally(() => setBusy(false));
        }}
        trigger={
          <Button type="button" size="sm" variant={props.destructive === true ? "destructive" : "default"} disabled={busy || props.disabled === true} data-testid={props.testId}>
            {busy ? t("form.busy") : t(props.labelKey)}
          </Button>
        }
      />
      {error !== null && <ProblemNotice error={error} testId={`${props.testId}-problem`} />}
    </div>
  );
}

/** A time in UTC as the kit shows it, or a dash. */
export function UTC({ iso }: { iso: string | null | undefined }) {
  const { lang } = useLang();
  const t = useT();
  if (iso === null || iso === undefined) return <>{t("common.dash")}</>;
  return <time dateTime={iso}>{fmtTimeUTC(iso, lang)}</time>;
}

/** A labelled section of a page. */
export function Section({ titleKey, vars, children, testId }: { titleKey: string; vars?: Vars; children: ReactNode; testId?: string }) {
  const t = useT();
  return (
    <section className="flex flex-col gap-2 px-4 py-3" aria-label={t(titleKey, vars)} data-testid={testId}>
      <h2 className="m-0 text-base font-semibold">{t(titleKey, vars)}</h2>
      {children}
    </section>
  );
}
